// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * html-char-packer.js — HTML charset packing engine. Repacks the JS payload into a
 * minified unpacker that rebuilds it from unique-character indices harvested
 * from the page's own HTML. Fixed-width base-93 index tokens with run-length
 * encoding; characters missing from the HTML are stored behind a literal
 * marker. The original JS is stripped from the HTML, the rebuilt JS executes
 * via indirect eval (global scope, no <script> element added).
 *
 * Pure computation over strings — no parsing library improves on the shared
 * regex layer here, so this engine uses only engine-utils imports.
 */

import {
  extractUniqueChars, jsStringLiteral, stripOriginalJs, injectBeforeClose, log,
} from '../lib/engine-utils.js';

const MARKER_LIT = '!';
const MARKER_RUN = '#';
const DIGITS = [];
for (let c = 32; c < 127; c++) {
  const ch = String.fromCharCode(c);
  if (ch !== MARKER_LIT && ch !== MARKER_RUN) DIGITS.push(ch);
}
const BASE = DIGITS.length; // 93

// ------------------------------------------------------------------ packing
// UTF-16 code-unit iteration on both encode and decode sides keeps surrogate
// pairs intact (fixes the Python original's codepoint/code-unit mismatch).
function indexWidth(charsetLen) {
  let width = 1;
  while (Math.pow(BASE, width) < charsetLen) width++;
  return width;
}
function encodeInt(n, width) {
  let s = '';
  for (let i = 0; i < width; i++) { s = DIGITS[n % BASE] + s; n = (n / BASE) | 0; }
  return s;
}
function pack(js, charmap, width) {
  const out = [];
  const n = js.length;
  let i = 0;
  while (i < n) {
    const ch = js[i];
    let j = i + 1;
    while (j < n && js[j] === ch) j++;
    const run = j - i;
    i = j;
    out.push(charmap.has(ch) ? encodeInt(charmap.get(ch), width) : MARKER_LIT + ch);
    let extra = run - 1;
    while (extra > 0) {
      const take = Math.min(extra, BASE - 1);
      out.push(MARKER_RUN + DIGITS[take]);
      extra -= take;
    }
  }
  return out.join('');
}
function unpack(packed, charset, width) {
  const dmap = new Map(DIGITS.map((d, i) => [d, i]));
  const out = [];
  let last = null, i = 0;
  while (i < packed.length) {
    const c = packed[i];
    if (c === MARKER_RUN) {
      const r = dmap.get(packed[i + 1]);
      i += 2;
      for (let k = 0; k < r; k++) out.push(last);
    } else if (c === MARKER_LIT) {
      last = packed[i + 1];
      out.push(last);
      i += 2;
    } else {
      let num = 0;
      for (let k = 0; k < width; k++) num = num * BASE + dmap.get(packed[i++]);
      last = charset[num];
      out.push(last);
    }
  }
  return out.join('');
}

// --------------------------------------------------------------- injectable
// Indirect eval (0,eval)(...) executes in GLOBAL scope — top-level
// declarations land like a real <script> tag, with no DOM element added.
const UNPACKER_TEMPLATE =
  '<script>(function(){' +
  'var C=__CHARSET__,P=__PACKED__,W=__WIDTH__,D={},n=0,i=0,c,k,l,o="";' +
  'for(c=32;c<127;c++)(k=String.fromCharCode(c))!="!"&&k!="#"&&(D[k]=n++);' +
  'while(i<P.length)' +
  'if((c=P[i])=="#"){k=D[P[++i]];i++;o+=Array(k+1).join(l)}' +
  'else if(c=="!"){o+=l=P[++i];i++}' +
  'else{for(k=0,n=0;n<W;n++)k=k*93+D[P[i++]];o+=l=C[k]}' +
  '(0,eval)(o)})()' +
  '</script>';

function buildBlock(html, js) {
  if (!js) throw new Error('JavaScript payload is empty.');

  const charset = extractUniqueChars(html);
  const charmap = new Map();
  for (let i = 0; i < charset.length; i++) charmap.set(charset[i], i);
  const width = indexWidth(charset.length);
  const packed = pack(js, charmap, width);

  if (unpack(packed, charset, width) !== js)
    throw new Error('PACKER BUG — round-trip mismatch, output not emitted.');

  const block = UNPACKER_TEMPLATE
    .replace('__WIDTH__', String(width))
    .replace('__CHARSET__', jsStringLiteral(charset))
    .replace('__PACKED__', jsStringLiteral(packed));

  const missing = [...new Set([...js].filter((ch) => !charmap.has(ch)))].sort().join('');
  const ratio = js ? ((packed.length / js.length) * 100).toFixed(1) : '0';
  const stats = [
    `charset size .............. ${charset.length} unique HTML chars`,
    `index token width ......... ${width} base-${BASE} digit(s)`,
    `JS chars not in HTML ...... ${missing.length}${missing ? ` ("${missing}")` : ''}`,
    `original JS ............... ${js.length} chars`,
    `packed stream ............. ${packed.length} chars (${ratio}%)`,
    `injected block total ...... ${block.length} chars`,
    'round-trip verified ....... rebuilt JS == source JS',
  ];
  return { block, stats };
}

export const engine = {
  id: 'html-char-packer',
  label: 'HTML Charset Packer',
  description:
    'Repacks the JS payload so it rebuilds at runtime from character indices taken ' +
    'from the HTML itself (base-93 RLE stream, literal fallback for missing chars). ' +
    'Executed in memory via indirect eval; original JS stripped from the page.',

  execute({ html, js }) {
    const { block, stats } = buildBlock(html, js);
    const stripped = stripOriginalJs(html, js);
    return {
      html: injectBeforeClose(stripped, block),
      stdout: log('HTML-CHAR-PACKER', ...stats),
      stderr: '',
    };
  },
};
export default engine;
