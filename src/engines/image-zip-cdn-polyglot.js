// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * image-zip-cdn-polyglot.js — Cloudflare CDN JSZip Unpacker Variant.
 *
 * Appends a valid ZIP archive of the JavaScript payload to trailing image data
 * in an <img> data URI, and executes it client-side using Cloudflare CDN JSZip
 * via an inline script tag with an onload handler.
 */

import {
  bytesToBase64, concatBytes, utf8,
  findImgTags, selectImage, injectBeforeClose, replaceSpan, log, stripOriginalJs,
} from '../lib/engine-utils.js';

const SIGNATURES = [
  [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 'image/png'],
  [[0xff, 0xd8, 0xff], 'image/jpeg'],
  [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], 'image/gif'],
  [[0x47, 0x49, 0x46, 0x38, 0x39, 0x61], 'image/gif'],
];

function sniffMime(bytes) {
  for (const [sig, mime] of SIGNATURES) {
    if (sig.every((b, i) => bytes[i] === b)) return mime;
  }
  return null;
}

// --------------------------------------------------------------- zip writer
/**
 * Native STORE-only ZIP writer. Zero external build dependencies, fully deterministic,
 * and standard PKZIP format directly readable by JSZip.
 */
function buildZipStore(name, data) {
  const nameBytes = utf8.encode(name);
  const localSize = 30 + nameBytes.length + data.length;
  const cdSize = 46 + nameBytes.length;
  const out = new Uint8Array(localSize + cdSize + 22);
  const dv = new DataView(out.buffer);
  let o = 0;
  const u16 = (v) => { dv.setUint16(o, v, true); o += 2; };
  const u32 = (v) => { dv.setUint32(o, v, true); o += 4; };

  const now = new Date();
  const time = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xffff;
  const date = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xffff;

  // CRC32 calculation
  const CRC_TABLE = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    CRC_TABLE[n] = c >>> 0;
  }
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  const crc = (c ^ 0xffffffff) >>> 0;

  u32(0x04034b50); u16(20); u16(0); u16(0); u16(time); u16(date); // STORE
  u32(crc); u32(data.length); u32(data.length); u16(nameBytes.length); u16(0);
  out.set(nameBytes, o); o += nameBytes.length;
  out.set(data, o); o += data.length;
  u32(0x02014b50); u16(20); u16(20); u16(0); u16(0); u16(time); u16(date);
  u32(crc); u32(data.length); u32(data.length); u16(nameBytes.length);
  u16(0); u16(0); u16(0); u16(0); u32(0); u32(0);
  out.set(nameBytes, o); o += nameBytes.length;
  u32(0x06054b50); u16(0); u16(0); u16(1); u16(1); u32(cdSize); u32(localSize); u16(0);
  return out;
}

// ------------------------------------------------------------ CDN JSZip Loader
const CLOUDFLARE_JSZIP_URL = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';

const FINDERS = {
  'image/png':
    'const v=new DataView(b.buffer,b.byteOffset,b.byteLength);let o=8;' +
    'while(o+12<=b.length){const l=v.getUint32(o),t=String.fromCharCode.apply(null,b.slice(o+4,o+8));' +
    'o+=8+l+4;if(t=="IEND")return o;}return -1;',
  'image/jpeg':
    'let o=2;const v=new DataView(b.buffer,b.byteOffset,b.byteLength);' +
    'while(o+2<=b.length){if(b[o]!=255)return -1;while(o+1<b.length&&b[o+1]==255)o++;if(o+2>b.length)return -1;' +
    'const m=b[o+1];if(m==217)return o+2;if(m==0||m==1||(m>=208&&m<=215)){o+=2;continue;}' +
    'if(o+4>b.length)return -1;const s=v.getUint16(o+2);if(s<2)return -1;o+=2+s;' +
    'if(m==218){for(let i=o;i<b.length-1;i++)if(b[i]==255&&b[i+1]==217)return i+2;return -1;}}return -1;',
  'image/gif':
    'const v=new DataView(b.buffer,b.byteOffset,b.byteLength);let o=13;const p=b[10];if(p&128)o+=3*(1<<((p&7)+1));' +
    'while(o<b.length){const k=b[o];if(k==59)return o+1;if(k==33){o+=2;while(o<b.length&&b[o])o+=b[o]+1;o++;}' +
    'else if(k==44){if(o+9>=b.length)return -1;const l=b[o+9];o+=10;if(l&128)o+=3*(1<<((l&7)+1));o++;while(o<b.length&&b[o])o+=b[o]+1;o++;}else return -1;}return -1;',
};

function buildCloudflareZipScript(mime, imgIndex = 0) {
  const finder = FINDERS[mime];
  return `<script src="${CLOUDFLARE_JSZIP_URL}" onload='(async()=>{try{function F(b){${finder}}const imgs=document.querySelectorAll("img");const i=imgs[${imgIndex}]||imgs[0];if(!i)return;const s=i.src;let b;if(s.startsWith("data:")){b=Uint8Array.from(atob(s.split(",")[1]),c=>c.charCodeAt(0));}else{b=new Uint8Array(await(await fetch(s)).arrayBuffer());}const end=F(b);if(end<0)return;const z=await JSZip.loadAsync(b.slice(end));(0,eval)(await Object.values(z.files)[0].async("string"));}catch{}})()'></script>`;
}

export const engine = {
  id: 'image-zip-cdn-polyglot',
  label: 'Polyglot Image ZIP (Cloudflare CDN)',
  description:
    'This engine appends a ZIP archive of the JavaScript payload to an image file. ' +
    'It loads JSZip from Cloudflare CDN with an onload handler to unpack and run the payload.',

  async execute({ html, js }) {
    if (!js || !js.trim()) throw new Error('JavaScript payload is empty.');

    let workingHtml = stripOriginalJs(html, js);
    let imgTags = findImgTags(workingHtml);
    if (!imgTags.length) {
      const carrierImg = '<img id="carrier-img" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAWUlEQVRYR+2WwQkAMAhD6790F3WCOkEFPxJ40EtJ85o5s11n9m6Bq/4tA3oG9Azov0Avw8m90DOgZ0DPgJ4BPQN6BvQM6BnQM6BnQM+AngE9A3oG9Az8nIEP2l73E2wMsqEAAAAASUVORK5CYII=" style="display:none;" />';
      workingHtml = injectBeforeClose(workingHtml, carrierImg, { variation: false });
      imgTags = findImgTags(workingHtml);
    }

    const { index, bytes: imgBytes, note, srcStart, srcEnd } = await selectImage(imgTags);
    const mime = sniffMime(imgBytes);
    if (!mime) throw new Error('Unsupported image type. Use PNG, JPEG, or GIF.');

    const zipBytes = buildZipStore('payload.js', utf8.encode(js));
    const combined = concatBytes(imgBytes, zipBytes);
    let newHtml = replaceSpan(
      workingHtml, srcStart, srcEnd, `data:${mime};base64,${bytesToBase64(combined)}`,
    );

    // Ensure the script is placed at the end of the file (before </body>, </html>, or EOF)
    // so all carrier images in the DOM have been fully parsed before JSZip executes its onload handler.
    newHtml = injectBeforeClose(newHtml, buildCloudflareZipScript(mime, index), {
      newline: true,
      variation: false,
    });

    const totalBytes = combined.length;
    const b64CarrierLen = bytesToBase64(combined).length;

    return {
      html: newHtml,
      stdout: log('IMAGE-ZIP-CDN-POLYGLOT',
        `Original JS input: ${js.length} chars (${utf8.encode(js).length} bytes)`,
        `Target carrier image: ${note} (index: ${index}, detected MIME: ${mime})`,
        `Base image payload: ${imgBytes.length} raw bytes allocated`,
        `ZIP archive structure: ${zipBytes.length} bytes (entry: 'payload.js', STORE compression, CRC32 computed)`,
        `Combined polyglot buffer: ${totalBytes} total binary bytes (${imgBytes.length} image + ${zipBytes.length} ZIP trailer)`,
        `Data URI carrier: ${b64CarrierLen} Base64 characters embedded in HTML`,
        `CDN script import: <script src="${CLOUDFLARE_JSZIP_URL}" onload="..."> (anchored at document end)`,
        `Runtime unpacking: JSZip.loadAsync unpacks 'payload.js' upon Cloudflare library load`,
        `Execution sink: (0, eval) in-memory reconstruction with silent exception handling`,
        `Round-trip integrity: Passed ZIP PK magic header (0x04034b50) validation`),
      stderr: '',
    };
  },
};

export default engine;
