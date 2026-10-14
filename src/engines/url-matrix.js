// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * url-matrix.js — Port of drJekyll.py. Every character of the JS payload
 * is remapped onto literal Node.js documentation URL strings; characters not
 * found (uppercase, emoji, ...) are rebuilt via hex codepoint instructions.
 * Round-trip verified before output. The obfuscated result is injected into
 * the HTML and any inline copy of the original JS is stripped.
 *
 * Pure computation — no parsing library improves on the shared regex layer
 * here, so this engine uses only engine-utils imports.
 */

import { bytesToBase64, stripOriginalJs, injectBeforeClose, log } from '../lib/engine-utils.js';

const URLS = [
  'https://nodejs.org/api/crypto.html',
  'https://nodejs.org/api/querystring.html',
  'https://nodejs.org/api/zlib.html',
  'https://nodejs.org/api/xml.html',
  'https://nodejs.org/api/webcrypto.html',
  'https://nodejs.org/api/http2.html',
  'https://nodejs.org/api/stream.html',
  'https://nodejs.org/api/url.html',
  'https://nodejs.org/download/release/v26.7.0/docs/api/',
  'https://nodejs.org/download/release/v25.1.0/docs/api/',
  'https://nodejs.org/download/release/v24.5.0/docs/api/',
  'https://nodejs.org/download/release/v23.11.1/docs/api/',
  'https://nodejs.org/download/release/v22.18.0/docs/api/',
  'https://nodejs.org/download/release/v20.19.4/docs/api/',
  'https://nodejs.org/download/release/v18.20.8/docs/api/',
  'https://nodejs.org/download/release/v16.20.2/docs/api/',
  'https://nodejs.org/download/release/v14.21.3/docs/api/',
];

function buildCharacterMaps(urlStrings) {
  const charMap = new Map();
  urlStrings.forEach((text, urlIdx) => {
    for (let charIdx = 0; charIdx < text.length; charIdx++) {
      const ch = text[charIdx];
      if (!charMap.has(ch)) charMap.set(ch, [urlIdx, charIdx]);
    }
  });
  const hexMap = new Map();
  for (const hc of '0123456789abcdef') {
    if (charMap.has(hc)) hexMap.set(hc, charMap.get(hc));
    else if (hc === 'f') hexMap.set(hc, [-1, -1]); // sentinel byte 255 -> (!1+"")[0]
    else throw new Error(`Hex character '${hc}' missing from URL strings.`);
  }
  return { charMap, hexMap };
}

function packInstructions(instructions) {
  const buf = [];
  for (const ins of instructions) {
    if (ins[0] === 0) buf.push(0, ins[1], ins[2]);
    else {
      const data = ins.slice(1);
      buf.push(1, data.length / 2);
      for (let j = 0; j < data.length; j += 2) {
        const [u, c] = [data[j], data[j + 1]];
        if (u === -1) buf.push(255); // lone sentinel for hex digit 'f'
        else buf.push(u, c);
      }
    }
  }
  return bytesToBase64(Uint8Array.from(buf));
}

// Mirror of the embedded decoder: round-trip self-test
function unpackAndVerify(b64, urlStrings, original) {
  const s = atob(b64);
  let i = 0, rebuilt = '';
  while (i < s.length) {
    const t = s.charCodeAt(i++);
    if (t === 0) {
      rebuilt += urlStrings[s.charCodeAt(i)][s.charCodeAt(i + 1)];
      i += 2;
    } else {
      const n = s.charCodeAt(i++);
      let h = '';
      for (let k = 0; k < n; k++) {
        const u = s.charCodeAt(i++);
        if (u === 255) h += 'f';
        else { h += urlStrings[u][s.charCodeAt(i)]; i++; }
      }
      rebuilt += String.fromCodePoint(parseInt(h, 16));
    }
  }
  return rebuilt === original;
}

function renderTemplate(year, urlsJson, payloadB64) {
  return `/*
 * Copyright (c) ${year} YOUR-COMPANY, INC. All Rights Reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL. This file is a trade secret of the copyright
 * holder and is protected under the Defend Trade Secrets Act (18 U.S.C. 1836)
 * and applicable law. It is licensed for use only under the terms of a
 * written agreement and may not be copied, disclosed, decompiled, or
 * reverse-engineered except as expressly permitted therein. The embedded
 * mapping onto the referenced URL strings is a verifiable fingerprint of
 * origin; unauthorized extraction or reuse is misappropriation. Provided "AS
 * IS" without warranty of any kind. Governing law: State of Delaware, USA.
 */
const _d=${urlsJson},_b="${payloadB64}";let _f;try{_f=atob(_b)}catch(e){_f=Buffer.from(_b,"base64").toString("binary")};(function(){try{let _p='',i=0;while(i<_f.length){const t=_f.charCodeAt(i++);if(t===0){_p+=_d[_f.charCodeAt(i++)][_f.charCodeAt(i++)]}else{const n=_f.charCodeAt(i++);let _h='';for(let k=0;k<n;k++){const u=_f.charCodeAt(i++);_h+=u===255?(!1+"")[0]:_d[u][_f.charCodeAt(i++)]}_p+=String.fromCodePoint(parseInt(_h,16))}}new Function(_p)();}catch(e){console.error("Matrix corrupted.",e)}}());`;
}

export const engine = {
  id: 'url-matrix',
  label: 'URL String Matrix (Dr. Jekyll)',
  description:
    'Obfuscates the JS payload by mapping every character onto literal Node.js doc ' +
    'URL strings (hex fallback for missing chars), round-trip verified, then injected.',

  execute({ html, js }) {
    // Byte-accurate invariant: url_idx and char_idx must each fit in one byte
    // (255 reserved as the 'f' sentinel). Checked inside execute (NOT at module
    // scope) so a failure can never break import.meta.glob discovery.
    if (URLS.length >= 255 || URLS.some((u) => u.length >= 255))
      throw new Error('URL dataset too large for byte packing');

    const { charMap, hexMap } = buildCharacterMaps(URLS);

    const instructions = [];
    for (const ch of js) { // iterate by codepoint, mirroring Python
      if (charMap.has(ch)) {
        const [u, c] = charMap.get(ch);
        instructions.push([0, u, c]);
      } else {
        const ins = [1];
        for (const hc of ch.codePointAt(0).toString(16))
          ins.push(hexMap.get(hc)[0], hexMap.get(hc)[1]);
        instructions.push(ins);
      }
    }

    const payloadB64 = packInstructions(instructions);
    if (!unpackAndVerify(payloadB64, URLS, js))
      throw new Error('PACKER BUG — packed payload does not round-trip to the original input.');

    const outJs = renderTemplate(new Date().getFullYear(), JSON.stringify(URLS), payloadB64);
    const stripped = stripOriginalJs(html, js);
    const result = injectBeforeClose(stripped, `<script>\n${outJs}\n</script>`);

    return {
      html: result,
      stdout: log('URL-MATRIX',
        `Round-trip verified. Obfuscated ${js.length} chars of JS into ${outJs.length} chars.`),
      stderr: '',
    };
  },
};
export default engine;
