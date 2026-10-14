// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * zip-appender.js — Port of appender.py (build_stego_page).
 * Picks an <img> (prefers one already base64-encoded, else the largest
 * fetchable one), appends a ZIP of the JS payload as trailing image data,
 * inlines the result as a base64 data URI, and injects a debug onload
 * unpacker.
 *
 * ZIP container writing delegated to JSZip (cdnjs UMD, same script the
 * embedded debug unpacker uses — zero incremental network cost when both
 * run). Falls back to a native STORE-only ZIP writer if the CDN is
 * unreachable, so the engine always produces valid output, online or off.
 */

import {
  bytesToBase64, concatBytes, utf8,
  loadUmd,
  findImgTags, selectImage, injectBeforeClose, replaceSpan, log,
} from '../lib/engine-utils.js';

const JSZIP_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';

const SIGNATURES = [
  [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 'image/png'],
  [[0xff, 0xd8, 0xff], 'image/jpeg'],
  [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], 'image/gif'],
  [[0x47, 0x49, 0x46, 0x38, 0x39, 0x61], 'image/gif'],
];
function sniffMime(bytes) {
  for (const [sig, mime] of SIGNATURES)
    if (sig.every((b, i) => bytes[i] === b)) return mime;
  return null;
}

// --------------------------------------------------------------- zip writer
/**
 * Preferred path: JSZip from the CDN (handles crc32, deflate, the central
 * directory, and datetime fields). Only loaded once per session; cached on
 * window by loadUmd.
 */
async function buildZipJSZip(name, data) {
  const JSZip = await loadUmd(JSZIP_CDN, 'JSZip');
  const z = new JSZip();
  z.file(name, data);
  return z.generateAsync({
    type: 'uint8array',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 },
  });
}

/**
 * Offline fallback: minimal native STORE-only ZIP. No deflate, but still a
 * perfectly valid zip readable by any unzipper.
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

  // CRC32 is mandatory even for STORE entries
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

async function buildZip(name, data) {
  try {
    return await buildZipJSZip(name, data);
  } catch {
    return buildZipStore(name, data); // offline / CDN failure: still valid
  }
}

// ------------------------------------------------------------ debug loaders
// Locators for the end of image data per container format; trailing ZIP
// bytes after these offsets are safely ignored by the format's decoders.
const FINDERS = {
  'image/png':
    'const v=new DataView(b.buffer,b.byteOffset,b.byteLength);let o=8;' +
    'while(o+8<=b.length){const l=v.getUint32(o),t=String.fromCharCode.apply(null,b.slice(o+4,o+8));' +
    'o+=8+l+4;if(t=="IEND")return o;}return -1;',
  'image/jpeg':
    'let o=2;const v=new DataView(b.buffer,b.byteOffset,b.byteLength);' +
    'while(o+4<=b.length){const m=b[o+1];if(m==217)return o+2;if(m>=208&&m<=215){o+=2;continue;}' +
    'const s=v.getUint16(o+2);o+=2+s;if(m==218){for(let i=o;i<b.length-1;i++)if(b[i]==255&&b[i+1]==217)return i+2;return -1;}}return -1;',
  'image/gif':
    'let o=13;const p=b[10];if(p&128)o+=3*(1<<((p&7)+1));' +
    'while(o<b.length){const k=b[o];if(k==59)return o+1;if(k==33){o+=2;while(b[o])o+=b[o]+1;o++;}' +
    'else if(k==44){const l=b[o+9];o+=10;if(l&128)o+=3*(1<<((l&7)+1));o++;while(b[o])o+=b[o]+1;o++;}else return -1;}return -1;',
};
function buildDebugScript(mime, imgIndex) {
  const finder = FINDERS[mime];
  return `<script src="${JSZIP_CDN}" onload='(async()=>{function F(b){${finder}}` +
    `const i=document.querySelectorAll("img")[${imgIndex}],s=i.src;let b;` +
    `if(s.startsWith("data:")){b=Uint8Array.from(atob(s.split(",")[1]),c=>c.charCodeAt(0));}` +
    `else{b=new Uint8Array(await(await fetch(s)).arrayBuffer());}` +
    `const z=await JSZip.loadAsync(b.slice(F(b)));` +
    `eval(await Object.values(z.files)[0].async("string"));})()'></script>`;
}

export const engine = {
  id: 'zip-appender',
  label: 'ZIP Trailing-Data Appender',
  description:
    'Appends a ZIP of the JS payload as trailing data after an <img> (PNG/JPEG/GIF), ' +
    'inlines the result as a base64 data URI, and injects a debug onload unpacker. ' +
    'ZIP writing via JSZip (CDN) with an offline STORE-only fallback.',

  async execute({ html, js }) {
    const imgTags = findImgTags(html);
    if (!imgTags.length) throw new Error('No <img src=...> tags found in the page.');

    const { index, bytes: imgBytes, note, srcStart, srcEnd } = await selectImage(imgTags);
    const mime = sniffMime(imgBytes);
    if (!mime) throw new Error('Unsupported image type. Use PNG, JPEG, or GIF.');

    const zipBytes = await buildZip('payload.js', utf8.encode(js));
    const combined = concatBytes(imgBytes, zipBytes); // single allocation
    let newHtml = replaceSpan(
      html, srcStart, srcEnd, `data:${mime};base64,${bytesToBase64(combined)}`,
    );

    newHtml = injectBeforeClose(newHtml, buildDebugScript(mime, index), { newline: false });

    return {
      html: newHtml,
      stdout: log('ZIP-APPENDER',
        `Selected image ${note}`,
        `${imgBytes.length} image bytes + ${zipBytes.length} zip bytes (${mime})`,
        'Debug unpacker injected (JSZip CDN is required to view it).'),
      stderr: '',
    };
  },
};
export default engine;
