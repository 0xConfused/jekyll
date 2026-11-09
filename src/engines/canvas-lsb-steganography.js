// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * canvas-lsb-steganography.js — Port of stego.py. Hides the JS payload in an <img>'s pixels
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
  stripOriginalJs, injectBeforeClose,
} from '../lib/engine-utils.js';

// Debug onload extractor (`this` = the image). Uses lossless TextDecoder
// to guarantee multi-byte UTF-8 payloads execute without URIError.
const DEBUG_ONLOAD =
  'if(!window.__lsb_ok){try{let t=this,c=document.createElement(`canvas`),x=c.getContext(`2d`),' +
  'W=c.width=t.naturalWidth||t.width||32,H=c.height=t.naturalHeight||t.height||32;' +
  'x.drawImage(t,0,0,W,H);let d=x.getImageData(0,0,W,H).data,u=[],b=0,n=0;' +
  'for(let p=0;p<d.length;p+=4)for(let k of @){b=b*2+d[p+k]%2;' +
  'if(++n===8){if(!b){window.__lsb_ok=1;(0,eval)(new TextDecoder().decode(new Uint8Array(u)));return;}' +
  'u.push(b);b=n=0;}}}catch(e){}}';

// Decode any browser-supported image to RGBA, alpha flattened onto white
// (canvas premultiplication scrambles LSBs in transparent regions).
async function decodeToRgba(bytes) {
  if (typeof createImageBitmap === 'function') {
    try {
      const blob = new Blob([bytes]);
      let bmp;
      try {
        bmp = await createImageBitmap(blob, { colorSpaceConversion: 'none' });
      } catch {
        bmp = await createImageBitmap(blob);
      }
      const w = bmp.width, h = bmp.height;
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(bmp, 0, 0, w, h);
      bmp.close?.();
      return { data: new Uint8Array(ctx.getImageData(0, 0, w, h).data), w, h, canvas, ctx };
    } catch {}
  }

  // Universal HTMLImageElement fallback
  return new Promise((resolve, reject) => {
    const img = new Image();
    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(img, 0, 0, w, h);
      resolve({ data: new Uint8Array(ctx.getImageData(0, 0, w, h).data), w, h, canvas, ctx });
    };
    img.onerror = (e) => {
      URL.revokeObjectURL(url);
      reject(new Error(`Could not decode image via HTMLImageElement: ${e?.message || 'load error'}`));
    };
    img.src = url;
  });
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
  ctx.putImageData(new ImageData(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength), w, h), 0, 0);
  if (canvas.toBlob) {
    try {
      const blob = await new Promise((res, rej) =>
        canvas.toBlob((b) => (b ? res(b) : rej(new Error('PNG encoding failed'))), 'image/png'));
      return new Uint8Array(await blob.arrayBuffer());
    } catch {}
  }
  // toDataURL fallback
  const dataUrl = canvas.toDataURL('image/png');
  const b64 = dataUrl.split(',')[1];
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// Self-check: re-decode the emitted PNG and read the LSBs back out.
async function extractLsb(pngBytes, channels) {
  let d;
  if (typeof createImageBitmap === 'function') {
    try {
      const blob = new Blob([pngBytes]);
      let bmp;
      try {
        bmp = await createImageBitmap(blob, { colorSpaceConversion: 'none' });
      } catch {
        bmp = await createImageBitmap(blob);
      }
      const c = document.createElement('canvas');
      c.width = bmp.width; c.height = bmp.height;
      const x = c.getContext('2d', { willReadFrequently: true });
      x.drawImage(bmp, 0, 0, c.width, c.height);
      bmp.close?.();
      d = new Uint8Array(x.getImageData(0, 0, c.width, c.height).data);
    } catch {}
  }
  if (!d) {
    d = await new Promise((resolve, reject) => {
      const img = new Image();
      const blob = new Blob([pngBytes]);
      const url = URL.createObjectURL(blob);
      img.onload = () => {
        URL.revokeObjectURL(url);
        const c = document.createElement('canvas');
        c.width = img.naturalWidth || img.width;
        c.height = img.naturalHeight || img.height;
        const x = c.getContext('2d', { willReadFrequently: true });
        x.drawImage(img, 0, 0, c.width, c.height);
        resolve(new Uint8Array(x.getImageData(0, 0, c.width, c.height).data));
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error('Extract decode failed'));
      };
      img.src = url;
    });
  }

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

// Quote-aware boundary helper to safely isolate full <img ...> tag
function findTagBoundaries(html, tagStart) {
  let inQuote = null;
  for (let i = tagStart; i < html.length; i++) {
    const ch = html[i];
    if (inQuote) {
      if (ch === inQuote) inQuote = null;
    } else {
      if (ch === '"' || ch === "'") inQuote = ch;
      else if (ch === '>') return { tagStart, tagEnd: i + 1 };
    }
  }
  return { tagStart, tagEnd: html.indexOf('>', tagStart) + 1 };
}

// Transform the carrier tag: replace src, remove conflicting srcset/lazy attrs, and inject onload strictly after src
function transformCarrierTag(originalTag, newSrc, channels) {
  const onloadCode = DEBUG_ONLOAD.replace('@', JSON.stringify(channels));
  let tag = originalTag;

  // Remove srcset, data-src, data-srcset, data-deferred, loading="lazy"
  tag = tag.replace(/\s+srcset\s*=\s*(?:(?:"[^"]*")|(?:'[^']*')|[^\s>]+)/gi, '');
  tag = tag.replace(/\s+data-(?:src|srcset|deferred)\s*=\s*(?:(?:"[^"]*")|(?:'[^']*')|[^\s>]+)/gi, '');
  tag = tag.replace(/\s+loading\s*=\s*(?:(?:"[^"]*")|(?:'[^']*')|[^\s>]+)/gi, '');
  tag = tag.replace(/\s+onload\s*=\s*(?:(?:"[^"]*")|(?:'[^']*')|[^\s>]+)/gi, '');

  // Replace src and inject onload strictly after src
  const srcRegex = /\bsrc\s*=\s*(?:(?:"[^"]*")|(?:'[^']*')|[^\s>]+)/i;
  if (srcRegex.test(tag)) {
    tag = tag.replace(srcRegex, `src="${newSrc}" onload="${onloadCode}"`);
  } else {
    tag = tag.replace(/^<img\b/i, `<img src="${newSrc}" onload="${onloadCode}"`);
  }

  return tag;
}

export const engine = {
  id: 'canvas-lsb-steganography',
  label: 'Canvas LSB Steganography',
  description:
    'This engine embeds the JavaScript payload into the least significant bits of image pixels. ' +
    'An image load event handler extracts and executes the payload.',

  async execute({ html, js }) {
    if (js.includes('\x00'))
      throw new Error('Payload contains NUL bytes, which are used as the terminator.');
    const payload = concatBytes(utf8.encode(js), new Uint8Array([0])); // + 0x00 terminator
    const flagBytes = payload.subarray(0, payload.length - 1);

    // Standard engine parsing pipeline: strip inline original JS first
    let workingHtml = stripOriginalJs(html, js);
    let imgTags = findImgTags(workingHtml);
    if (!imgTags.length) {
      const carrierImg = '<img id="carrier-img" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAWUlEQVRYR+2WwQkAMAhD6790F3WCOkEFPxJ40EtJ85o5s11n9m6Bq/4tA3oG9Azov0Avw8m90DOgZ0DPgJ4BPQN6BvQM6BnQM6BnQM+AngE9A3oG9Az8nIEP2l73E2wMsqEAAAAASUVORK5CYII=" style="display:none;" />';
      workingHtml = injectBeforeClose(workingHtml, carrierImg);
      imgTags = findImgTags(workingHtml);
    }

    const { bytes: imgBytes, note, srcStart, srcEnd, tagStart, index: targetImgIndex } = await selectImage(imgTags);

    let { data: rgba, w, h, canvas, ctx } = await decodeToRgba(imgBytes);
    const neededBits = payload.length * 8;
    if (w * h * 3 < neededBits) {
      const minPixels = Math.ceil(neededBits / 3);
      const factor = Math.max(2, Math.ceil(Math.sqrt(minPixels / (w * h))));
      const newW = w * factor;
      const newH = h * factor;
      const scaledCanvas = document.createElement('canvas');
      scaledCanvas.width = newW;
      scaledCanvas.height = newH;
      const scaledCtx = scaledCanvas.getContext('2d', { willReadFrequently: true });
      scaledCtx.fillStyle = '#ffffff';
      scaledCtx.fillRect(0, 0, newW, newH);
      scaledCtx.drawImage(canvas, 0, 0, newW, newH);
      canvas = scaledCanvas;
      ctx = scaledCtx;
      w = newW;
      h = newH;
      rgba = new Uint8Array(ctx.getImageData(0, 0, w, h).data);
    }

    const channels = chooseChannels(w, h, neededBits);
    const chanName = channels.map((i) => 'rgb'[i]).join('');
    embedLsb(rgba, w, h, payload, channels);

    const pngBytes = await encodePng(canvas, ctx, rgba, w, h);
    const check = await extractLsb(pngBytes, channels);
    if (!bytesEqual(check, flagBytes))
      throw new Error('Self-check failed: extracted data does not match the payload.');

    const newSrc = `data:image/png;base64,${bytesToBase64(pngBytes)}`;
    const { tagEnd } = findTagBoundaries(workingHtml, tagStart);
    const carrierTag = workingHtml.slice(tagStart, tagEnd);
    const transformedTag = transformCarrierTag(carrierTag, newSrc, channels);
    let newHtml = workingHtml.slice(0, tagStart) + transformedTag + workingHtml.slice(tagEnd);

    // Guaranteed companion extractor ensures execution across all load cycles and browser states
    const companionScript =
      `<script>(function(){` +
      `function _ext(t){` +
      `if(window.__lsb_ok)return true;` +
      `var w=t.naturalWidth||t.width||0,h=t.naturalHeight||t.height||0;` +
      `if(!w||!h)return false;` +
      `try{` +
      `var c=document.createElement("canvas"),x=c.getContext("2d");` +
      `c.width=w;c.height=h;` +
      `x.drawImage(t,0,0,w,h);` +
      `var d=x.getImageData(0,0,w,h).data,u=[],chs=${JSON.stringify(channels)};` +
      `var b=0,n=0;` +
      `for(var p=0;p<d.length;p+=4)for(var k=0;k<chs.length;k++){` +
      `b=b*2+d[p+chs[k]]%2;` +
      `if(++n===8){` +
      `if(!b){window.__lsb_ok=1;(0,eval)(new TextDecoder().decode(new Uint8Array(u)));return true;}` +
      `u.push(b);b=n=0;` +
      `}` +
      `}` +
      `}catch(e){return false;}` +
      `return false;` +
      `}` +
      `function _findAndRun(){` +
      `if(window.__lsb_ok)return;` +
      `var target=document.querySelector('img[src^="data:image/png;base64,"]')||document.querySelectorAll("img")[${targetImgIndex}]||document.querySelector("img");` +
      `if(target){` +
      `if(!_ext(target)){` +
      `target.addEventListener("load",function(){_ext(target);});` +
      `var s=target.getAttribute("src")||target.src;` +
      `if(s&&s.indexOf("data:")===0){` +
      `var i=new Image();` +
      `i.onload=function(){_ext(i);};` +
      `i.src=s;` +
      `}` +
      `setTimeout(function(){_ext(target);},50);` +
      `setTimeout(function(){_ext(target);},200);` +
      `setTimeout(function(){_ext(target);},600);` +
      `}` +
      `}` +
      `}` +
      `if(document.readyState==="loading"){` +
      `document.addEventListener("DOMContentLoaded",_findAndRun);` +
      `window.addEventListener("load",_findAndRun);` +
      `}` +
      `_findAndRun();` +
      `setTimeout(_findAndRun,100);` +
      `setTimeout(_findAndRun,500);` +
      `})()</script>`;
    newHtml = injectBeforeClose(newHtml, companionScript, {
      variation: false,
    });

    const totalPixels = w * h;
    const totalBitCapacity = totalPixels * channels.length;
    const capacityUsage = (((flagBytes.length * 8) / totalBitCapacity) * 100).toFixed(2);

    return {
      html: newHtml,
      stdout: log('CANVAS-LSB-STEGANOGRAPHY',
        `Original JS input: ${js.length} chars (${new TextEncoder().encode(js).length} bytes)`,
        `Carrier image target: ${note} (dimensions: ${w}x${h}, ${totalPixels} pixels)`,
        `Channel allocation: '${chanName}' (${channels.length} bits/pixel, total capacity: ${totalBitCapacity} bits)`,
        `Payload packaging: ${flagBytes.length} payload bytes embedded (utilization: ${capacityUsage}%)`,
        `PNG binary synthesis: ${pngBytes.length} output PNG bytes with IDAT chunk re-encoding`,
        `In-memory extractor: HTML5 Canvas 2D context getImageData pixel parser generated`,
        `Execution sink: (0, eval) via TextDecoder with quiet error suppression`,
        `Round-trip integrity: Passed self-check verification (100% byte-for-byte fidelity)`,
        `Placement variation: Companion extractor injected across document boundaries`),
      stderr: '',
    };
  },
};
export default engine;
