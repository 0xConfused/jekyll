// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * dom-charset-packer.js — DOM charset packing engine. Repacks the JS payload into a
 * minified unpacker that rebuilds it from unique-character indices harvested
 * from the page's own HTML elements. Uses an optimized variable-width base-93
 * encoding scheme (single-character tokens for indices < W, two-character tokens
 * for indices >= W), seeded missing character tables, and adaptive run-length
 * encoding. The original JS is stripped from the HTML, and the reconstituted
 * payload executes via indirect global eval.
 *
 * Pure computation over strings — uses only engine-utils imports.
 */

import {
  extractUniqueChars, stripOriginalJs, injectBeforeClose, log,
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
// Variable-width base-93 index encoding:
// For symbols with index < W, encode as 1 single base-93 digit.
// For symbols with index >= W, encode as 2 base-93 digits:
//   d1 = W + Math.floor((k - W) / 93)
//   d2 = (k - W) % 93
// Reconstructed via: k = k * 93 + d2 - W * 92
// Run-length encoding uses '#' tokens only when it compresses data (run >= 3 for 1-char tokens).
function getOptimalWidthCutoff(totalChars) {
  if (totalChars <= 93) return 93;
  const maxW = Math.floor((8649 - totalChars) / 92);
  return Math.min(92, Math.max(1, maxW));
}

function encodeChar(idx, W) {
  if (idx < W) return DIGITS[idx];
  const rem = idx - W;
  const d1 = W + Math.floor(rem / BASE);
  const d2 = rem % BASE;
  return DIGITS[d1] + DIGITS[d2];
}

function pack(js, charmap, W) {
  const out = [];
  const n = js.length;
  let i = 0;
  while (i < n) {
    const ch = js[i];
    let j = i + 1;
    while (j < n && js[j] === ch) j++;
    const run = j - i;
    i = j;

    const tok = charmap.has(ch) ? encodeChar(charmap.get(ch), W) : MARKER_LIT + ch;
    out.push(tok);

    let extra = run - 1;
    if (extra > 0) {
      if (tok.length === 1 && extra <= 2) {
        out.push(tok.repeat(extra));
      } else {
        while (extra > 0) {
          const take = Math.min(extra, BASE - 1);
          out.push(MARKER_RUN + DIGITS[take]);
          extra -= take;
        }
      }
    }
  }
  return out.join('');
}

function unpack(packed, charset, W) {
  const dmap = new Map(DIGITS.map((d, i) => [d, i]));
  const out = [];
  let last = '', i = 0;
  while (i < packed.length) {
    const c = packed[i++];
    if (c === MARKER_RUN) {
      const r = dmap.get(packed[i++]);
      out.push(last.repeat(r));
    } else if (c === MARKER_LIT) {
      last = packed[i++];
      out.push(last);
    } else {
      let k = dmap.get(c);
      if (k >= W) {
        k = k * 93 + dmap.get(packed[i++]) - W * 92;
      }
      last = charset[k];
      out.push(last);
    }
  }
  return out.join('');
}

let nodeJsdom = null;
if (typeof window === 'undefined' && typeof process !== 'undefined') {
  try {
    const req = typeof require !== 'undefined' ? require : (0, eval)('require');
    if (typeof req === 'function') {
      const jsdomMod = req('jsdom');
      nodeJsdom = jsdomMod.JSDOM || jsdomMod.default?.JSDOM;
    }
  } catch {}
}

function extractFromElements(html) {
  let doc = null;
  if (typeof DOMParser !== 'undefined') {
    try {
      doc = new DOMParser().parseFromString(html, 'text/html');
    } catch {}
  }
  if (!doc && typeof window !== 'undefined' && window.document) {
    try {
      doc = document.implementation.createHTMLDocument('');
      doc.documentElement.innerHTML = html;
    } catch {}
  }
  if (!doc && nodeJsdom) {
    try {
      doc = new nodeJsdom(html).window.document;
    } catch {}
  }
  if (!doc && typeof process !== 'undefined') {
    try {
      const req = typeof require !== 'undefined' ? require : (0, eval)('require');
      if (typeof req === 'function') {
        const { JSDOM } = req('jsdom');
        doc = new JSDOM(html).window.document;
      }
    } catch {}
  }

  if (doc) {
    const all = doc.all || doc.getElementsByTagName('*');
    let C = '';
    for (let j = 0; j < all.length; j++) {
      const e = all[j];
      if (e.id === '_hcp') continue;
      let s = '<' + e.tagName.toLowerCase();
      if (e.attributes) {
        for (let i = 0; i < e.attributes.length; i++) {
          s += ' ' + e.attributes[i].name + '="' + e.attributes[i].value + '"';
        }
      }
      s += '>';
      if (e.childNodes) {
        for (let i = 0; i < e.childNodes.length; i++) {
          const cn = e.childNodes[i];
          if (cn.nodeType === 3) s += cn.nodeValue;
        }
      }
      s += '<\/' + e.tagName.toLowerCase() + '>';
      for (let k = 0; k < s.length; k++) if (C.indexOf(s[k]) < 0) C += s[k];
    }
    if (C.length > 0) return [...new Set(C)].sort().join('');
  }

  return [...new Set(extractUniqueChars(html))].sort().join('');
}

// --------------------------------------------------------------- injectable
// Rebuilds and runs script in memory by dynamically harvesting character tables
// from elements of document.all via an inline <script> block with indirect eval.
const UNPACKER_TEMPLATE =
  '<script id="_hcp">(function(){' +
  'var a=document.all||document.getElementsByTagName(\'*\'),C=\'\',j,k,i,e,s,cn,' +
  'cs=document.currentScript||document.getElementById(\'_hcp\'),' +
  'P=__PACKED__,W=__WIDTH__,M=__MISSING__,D={},p=0,c,l,o=\'\';' +
  'for(j=0;j<a.length;j++){' +
  'e=a[j];if(e===cs||e.id===\'_hcp\')continue;' +
  's=\'<\'+e.tagName.toLowerCase();' +
  'if(e.attributes)for(i=0;i<e.attributes.length;i++)s+=\' \'+e.attributes[i].name+\'="\'+e.attributes[i].value+\'"\';' +
  's+=\'>\';' +
  'if(e.childNodes)for(i=0;i<e.childNodes.length;i++){cn=e.childNodes[i];if(cn.nodeType===3)s+=cn.nodeValue;}' +
  's+=\'</\'+e.tagName.toLowerCase()+\'>\';' +
  'for(k=0;k<s.length;k++)if(C.indexOf(s[k])<0)C+=s[k];' +
  '}' +
  'C=[...new Set(C)].sort().join(\'\')+M;i=0;' +
  'for(c=32;c<127;c++)(k=String.fromCharCode(c))!=\'!\'&&k!=\'#\'&&(D[k]=p++);' +
  'while(i<P.length)' +
  'if((c=P[i++])===\'#\'){k=D[P[i++]];o+=l.repeat(k)}' +
  'else if(c===\'!\'){o+=l=P[i++]}' +
  'else{k=D[c];if(k>=W)k=k*93+D[P[i++]]-W*92;o+=l=C[k]}' +
  '(0,eval)(o);' +
  '})();</script>';

function buildBlock(html, js) {
  if (!js) throw new Error('JavaScript payload is empty.');

  // Extract unique character sequence directly matching document.all elements
  const charset = extractFromElements(html);
  const baseCharmap = new Set([...charset]);
  const missing = [...new Set([...js].filter((ch) => !baseCharmap.has(ch)))].join('');
  const fullCharset = charset + missing;

  const charmap = new Map();
  for (let i = 0; i < fullCharset.length; i++) charmap.set(fullCharset[i], i);

  const W = getOptimalWidthCutoff(fullCharset.length);
  const packed = pack(js, charmap, W);

  if (unpack(packed, fullCharset, W) !== js)
    throw new Error('PACKER BUG — round-trip mismatch, output not emitted.');

  const safeJson = JSON.stringify(packed).replace(/<\/script/gi, '<\\/script');
  const safeMissing = JSON.stringify(missing).replace(/<\/script/gi, '<\\/script');
  const block = UNPACKER_TEMPLATE
    .replace('__WIDTH__', String(W))
    .replace('__MISSING__', () => safeMissing)
    .replace('__PACKED__', () => safeJson);

  const ratio = js ? ((packed.length / js.length) * 100).toFixed(1) : '0';
  const stats = [
    `source charset ............ ${charset.length} unique HTML chars harvested via document.all elements`,
    `missing chars seeded ...... ${missing.length}${missing ? ` ("${missing}")` : ' (all characters found in markup)'}`,
    `total symbol table ........ ${fullCharset.length} characters in reconstruction dictionary`,
    `index token width ......... variable-width base-${BASE} (cutoff W=${W}, 1-char tokens for indices < ${W})`,
    `original JS ............... ${js.length} chars (${new TextEncoder().encode(js).length} bytes)`,
    `packed stream ............. ${packed.length} chars (${ratio}% payload ratio)`,
    `run-length encoding ....... adaptive RLE ('#' repeat tokens, threshold>=3 for 1-char tokens)`,
    `injected block total ...... ${block.length} chars (inline script carrier)`,
    `execution vector .......... indirect global eval inside inline <script> block`,
    `carrier element ........... <script id="_hcp">(function(){...})()</script>`,
    `round-trip verified ....... rebuilt JS == source JS (100% byte-for-byte fidelity)`,
  ];
  return { block, stats };
}

export const engine = {
  id: 'dom-charset-packer',
  label: 'DOM Charset Index Packer',
  description:
    'This engine encodes the JavaScript payload into character indices from the HTML page. ' +
    'It reconstructs and executes the code in memory with indirect evaluation.',

  execute({ html, js }) {
    const stripped = stripOriginalJs(html, js);
    const { block, stats } = buildBlock(stripped, js);
    return {
      html: injectBeforeClose(stripped, block, { newline: false }),
      stdout: log('DOM-CHARSET-PACKER', ...stats),
      stderr: '',
    };
  },
};
export default engine;
