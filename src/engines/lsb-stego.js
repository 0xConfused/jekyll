// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * lsb-stego.js — Port of stego.py. Hides the JS payload in an <img>'s pixels
 * using classic LSB steganography: lossless RGB PNG, row-major pixels,
 * MSB-first bits, a random ordered channel subset, 0x00 terminator.
 * The chosen image is flattened onto white (alpha kills LSBs under canvas
 * premultiplication) and re-encoded as PNG. Verified by re-decoding the
 * emitted PNG before injection; a debug onload extractor is added by default.
 *
 * Image decode/encode delegated to native createImageBitmap + canvas —
 * no JS library matches these for correctness or speed in a browser.
 */

import {
  bytesToBase64, bytesEqual, utf8, concatBytes,
  findImgTags, selectImage, parseTagAttributes, replaceSpan, secureChoice, log,
} from '../lib/engine-utils.js';

// Debug onload extractor (`this` = the image). FIXED: loop condition was
// `p-d.length` (worked only by accident); now `p<d.length`. Avoids
// quotes/</& so it is safe inside any quoted HTML attribute.
const DEBUG_ONLOAD =
  'let t=this,c=document.createElement(`canvas`),x=c.getContext(`2d`),' +
  'W=c.width=t.naturalWidth,H=c.height=t.naturalHeight;x.drawImage(t,0,0);' +
  'let d=x.getImageData(0,0,W,H).data,o=``,b=0,n=0;' +
  'for(let p=0;p<d.length;p+=4)for(let k of @){b=b*2+d[p+k]%2;' +
  'if(++n>7){if(!b){eval(decodeURIComponent(escape(o)));return}' +
  'o+=String.fromCharCode(b);b=n=0}}';

// Decode any browser-supported image to RGBA, alpha flattened onto white
// (canvas premultiplication scrambles LSBs in transparent regions).
async function decodeToRgba(bytes) {
  let bmp;
  try {
    bmp = await createImageBitmap(new Blob([bytes]));
  } catch (e) {
    throw new Error(`Could not decode image: ${e.message}`);
  }
  const w = bmp.width, h = bmp.height;
  const canvas = document.createElement('canvas');
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, w, h);
  ctx.drawImage(bmp, 0, 0);
  bmp.close?.();
  return { data: new Uint8Array(ctx.getImageData(0, 0, w, h).data), w, h, canvas, ctx };
}

function permutations(arr, k) {
  if (k === 1) return arr.map((x) => [x]);
  const res = [];
  for (let i = 0; i < arr.length; i++) {
    const rest = arr.filter((_, j) => j !== i);
    for (const p of permutations(rest, k - 1)) res.push([arr[i], ...p]);
  }
  return res;
}
function chooseChannels(w, h, payloadBits) {
  const options = [];
  for (const k of [1, 2, 3])
    if (w * h * k >= payloadBits) options.push(...permutations([0, 1, 2], k));
  if (!options.length)
    throw new Error(`Payload too large: need ${payloadBits} bits but even all three channels ` +
      `of a ${w}x${h} image hold only ${w * h * 3} bits.`);
  return secureChoice(options);
}

function embedLsb(rgba, w, h, payload, channels) {
  const neededBits = payload.length * 8;
  const capacityBits = w * h * channels.length;
  if (neededBits > capacityBits)
    throw new Error(`Payload too large: need ${neededBits} bits but the image holds only ` +
      `${capacityBits} bits (${capacityBits >> 3} bytes).`);
  let bitIdx = 0;
  for (let p = 0; p < w * h && bitIdx < neededBits; p++) {
    for (const ch of channels) {
      if (bitIdx >= neededBits) break;
      const bit = (payload[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
      const idx = p * 4 + ch;
      rgba[idx] = (rgba[idx] & 0xfe) | bit;
      bitIdx++;
    }
  }
}

async function encodePng(canvas, ctx, rgba, w, h) {
  ctx.putImageData(new ImageData(new Uint8ClampedArray(rgba.buffer), w, h), 0, 0);
  const blob = await new Promise((res, rej) =>
    canvas.toBlob((b) => (b ? res(b) : rej(new Error('PNG encoding failed'))), 'image/png'));
  return new Uint8Array(await blob.arrayBuffer());
}

// Self-check: re-decode the emitted PNG and read the LSBs back out.
async function extractLsb(pngBytes, channels) {
  const bmp = await createImageBitmap(new Blob([pngBytes]));
  const c = document.createElement('canvas');
  c.width = bmp.width; c.height = bmp.height;
  const x = c.getContext('2d', { willReadFrequently: true });
  x.drawImage(bmp, 0, 0);
  bmp.close?.();
  const d = new Uint8Array(x.getImageData(0, 0, c.width, c.height).data);
  const out = [];
  let b = 0, n = 0;
  for (let p = 0; p + 3 < d.length; p += 4) {
    for (const ch of channels) {
      b = b * 2 + (d[p + ch] & 1);
      if (++n > 7) {
        if (!b) return new Uint8Array(out); // 0x00 terminator
        out.push(b);
        b = n = 0;
      }
    }
  }
  return new Uint8Array(out);
}

// onload injection uses the shared sticky-attribute scanner; placement is
// random but always at a valid attribute boundary, never inside a value.
function injectDebugOnload(html, tagStart, channels) {
  const { spots, names } = parseTagAttributes(html, tagStart);
  if (names.includes('onload')) return html;
  const at = secureChoice(spots);
  const code = DEBUG_ONLOAD.replace('@', JSON.stringify(channels));
  return html.slice(0, at) + ` onload="${code}"` + html.slice(at);
}

export const engine = {
  id: 'lsb-stego',
  label: 'Image LSB Steganography',
  description:
    'Hides the JS payload in an <img> using classic LSB steganography (lossless ' +
    'PNG, random R/G/B channel subset, 0x00 terminator), verified via round-trip ' +
    're-decode, with an inline onload extractor for verification.',

  async execute({ html, js }) {
    if (js.includes('\x00'))
      throw new Error('Payload contains NUL bytes, which are used as the terminator.');
    const payload = concatBytes(utf8.encode(js), new Uint8Array([0])); // + 0x00 terminator
    const flagBytes = payload.subarray(0, payload.length - 1);

    const imgTags = findImgTags(html);
    if (!imgTags.length) throw new Error('No <img src=...> tags found in the page.');
    const { bytes: imgBytes, note, srcStart, srcEnd, tagStart } = await selectImage(imgTags);

    const { data: rgba, w, h, canvas, ctx } = await decodeToRgba(imgBytes);
    const channels = chooseChannels(w, h, payload.length * 8);
    const chanName = channels.map((i) => 'rgb'[i]).join('');
    embedLsb(rgba, w, h, payload, channels);

    const pngBytes = await encodePng(canvas, ctx, rgba, w, h);
    const check = await extractLsb(pngBytes, channels);
    if (!bytesEqual(check, flagBytes))
      throw new Error('Self-check failed: extracted data does not match the payload.');

    let newHtml = replaceSpan(html, srcStart, srcEnd, `data:image/png;base64,${bytesToBase64(pngBytes)}`);
    newHtml = injectDebugOnload(newHtml, tagStart, channels);

    return {
      html: newHtml,
      stdout: log('LSB-STEGO',
        `Selected image ${note}`,
        `Image is ${w}x${h}`,
        `Randomly chose LSB channels '${chanName}' (answer key; not stored in output)`,
        `Self-check passed: payload round-trips through the PNG (${pngBytes.length} PNG bytes, ${flagBytes.length} payload bytes).`),
      stderr: '',
    };
  },
};
export default engine;
