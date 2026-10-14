// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ============================================================================
 * ENGINE UTILITIES (src/lib/engine-utils.js)
 * Shared computational primitives and DOM helpers for injection engines.
 * ============================================================================
 */

/**
 * Returns a cryptographically random integer in [0, max).
 * @param {number} max
 * @returns {number}
 */
export function randInt(max) {
  if (max <= 0) return 0;
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

/**
 * Generates a random hexadecimal string of given byte length.
 * @param {number} length
 * @returns {string}
 */
export function randomHexId(length = 4) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Converts a Uint8Array or ArrayBuffer into a base64 string.
 * Uses chunking to prevent stack overflow on large inputs.
 * @param {Uint8Array|ArrayBuffer} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  const len = u8.byteLength;
  const chunkSize = 8192;
  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + chunkSize, len)));
  }
  return btoa(binary);
}

/**
 * Dynamically loads an ESM module from a remote URL.
 * @param {string} url
 * @returns {Promise<any>}
 */
export async function loadEsm(url) {
  /* @vite-ignore */
  return import(/* @vite-ignore */ url);
}

/**
 * Dynamically loads a UMD library script into document.head and resolves window[globalName].
 * @param {string} url
 * @param {string} globalName
 * @returns {Promise<any>}
 */
export async function loadUmd(url, globalName) {
  if (typeof window !== 'undefined' && window[globalName]) {
    return window[globalName];
  }
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = url;
    script.onload = () => {
      if (window[globalName]) {
        resolve(window[globalName]);
      } else {
        reject(new Error(`UMD library ${globalName} not found on window after loading ${url}`));
      }
    };
    script.onerror = (err) => reject(new Error(`Failed to load script ${url}: ${err}`));
    document.head.appendChild(script);
  });
}

/**
 * Formats multi-line diagnostic log messages for engine stdout.
 * @param {string} prefix
 * @param  {...string} messages
 * @returns {string}
 */
export function log(prefix, ...messages) {
  return messages.map((msg) => `[${prefix}] ${msg}`).join('\n');
}

/**
 * Extracts all unique characters appearing in an HTML string.
 * @param {string} html
 * @returns {string}
 */
export function extractUniqueChars(html) {
  const set = new Set(html);
  return Array.from(set).join('');
}

/**
 * Safely serializes a string into a valid JavaScript literal representation.
 * @param {string} str
 * @returns {string}
 */
export function jsStringLiteral(str) {
  return JSON.stringify(str);
}

/**
 * Strips occurrences of the original JS payload from the HTML source.
 * @param {string} html
 * @param {string} js
 * @returns {string}
 */
export function stripOriginalJs(html, js) {
  if (!js || !js.trim()) return html;
  const trimmed = js.trim();
  if (html.includes(trimmed)) {
    return html.replace(trimmed, '');
  }
  return html.replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gi, (match, scriptBody) => {
    if (scriptBody.trim() === trimmed || scriptBody.includes(trimmed)) {
      return '';
    }
    return match;
  });
}

/**
 * Injects payload before the closing </body>, </html>, or EOF.
 * @param {string} html
 * @param {string} payload
 * @param {{ newline?: boolean }} options
 * @returns {string}
 */
export function injectBeforeClose(html, payload, options = {}) {
  const nl = options.newline === false ? '' : '\n';
  const block = nl + payload + nl;
  if (html.includes('</body>')) {
    return html.replace('</body>', `${block}</body>`);
  }
  if (html.includes('</html>')) {
    return html.replace('</html>', `${block}</html>`);
  }
  return html + block;
}

/**
 * Compares two byte arrays for byte-by-byte equality.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * UTF-8 text encoder and decoder helper.
 */
export const utf8 = {
  encode(str) {
    return new TextEncoder().encode(str);
  },
  decode(bytes) {
    return new TextDecoder().decode(bytes);
  },
};

/**
 * Concatenates multiple byte arrays into a single Uint8Array allocation.
 * @param  {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
export function concatBytes(...arrays) {
  const totalLength = arrays.reduce((acc, curr) => acc + (curr ? curr.length : 0), 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    if (arr) {
      result.set(arr, offset);
      offset += arr.length;
    }
  }
  return result;
}

/**
 * Securely selects a random element from an array using crypto random values.
 * @template T
 * @param {T[]} arr
 * @returns {T}
 */
export function secureChoice(arr) {
  if (!arr || !arr.length) throw new Error('Cannot select from empty array');
  const index = randInt(arr.length);
  return arr[index];
}

/**
 * Replaces a character span [start, end) within a string.
 * @param {string} str
 * @param {number} start
 * @param {number} end
 * @param {string} replacement
 * @returns {string}
 */
export function replaceSpan(str, start, end, replacement) {
  return str.slice(0, start) + replacement + str.slice(end);
}

/**
 * Generates an in-memory fallback PNG (canvas or minimal 32x32 white image)
 * to ensure steganography works reliably even when external images fail to fetch.
 * @param {number} w
 * @param {number} h
 * @returns {Uint8Array}
 */
function generateFallbackPng(w = 32, h = 32) {
  if (typeof document !== 'undefined') {
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, w, h);
    const dataUrl = canvas.toDataURL('image/png');
    const b64 = dataUrl.split(',')[1];
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }
  return new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
    0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xff, 0xff, 0x3f,
    0x00, 0x05, 0xfe, 0x02, 0xfe, 0xdc, 0xcc, 0x59, 0xe7, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
  ]);
}

/**
 * Scans HTML for <img ...> elements and extracts positional spans of their src values.
 * @param {string} html
 * @returns {Array<{index: number, tag: string, tagStart: number, tagEnd: number, src: string, srcStart: number, srcEnd: number, isBase64: boolean}>}
 */
export function findImgTags(html) {
  const imgRegex = /<img\b([^>]*?)>/gi;
  const tags = [];
  let match;
  let index = 0;
  while ((match = imgRegex.exec(html)) !== null) {
    const fullTag = match[0];
    const attrs = match[1];
    const tagStart = match.index;
    const tagEnd = tagStart + fullTag.length;

    const srcRegex = /\bsrc\s*=\s*(?:(["'])(.*?)\1|([^\s>]+))/i;
    const srcMatch = srcRegex.exec(attrs);
    if (srcMatch) {
      const isQuoted = Boolean(srcMatch[1]);
      const srcValue = isQuoted ? srcMatch[2] : srcMatch[3];
      const attrMatchOffset = tagStart + match[0].indexOf(srcMatch[0]);
      let srcStart, srcEnd;
      if (isQuoted) {
        const quoteChar = srcMatch[1];
        const valStartInMatch = srcMatch[0].indexOf(quoteChar) + 1;
        srcStart = attrMatchOffset + valStartInMatch;
        srcEnd = srcStart + srcValue.length;
      } else {
        const eqIndex = srcMatch[0].indexOf('=');
        srcStart = attrMatchOffset + eqIndex + 1;
        while (srcStart < tagEnd && /\s/.test(html[srcStart])) srcStart++;
        srcEnd = srcStart + srcValue.length;
      }

      tags.push({
        index: index++,
        tag: fullTag,
        tagStart,
        tagEnd,
        src: srcValue,
        srcStart,
        srcEnd,
        isBase64: srcValue.startsWith('data:'),
      });
    }
  }
  return tags;
}

/**
 * Selects an image tag from findImgTags output and resolves its binary content.
 * @param {Array<any>} imgTags
 * @returns {Promise<{index: number, bytes: Uint8Array, note: string, srcStart: number, srcEnd: number, tagStart: number}>}
 */
export async function selectImage(imgTags) {
  if (!imgTags || !imgTags.length) {
    throw new Error('No images available in document.');
  }

  const b64Imgs = imgTags.filter((t) => t.isBase64);
  const candidate = b64Imgs.length > 0 ? b64Imgs[0] : imgTags[0];

  let bytes;
  let note = `image #${candidate.index}`;

  if (candidate.src.startsWith('data:')) {
    const commaIdx = candidate.src.indexOf(',');
    const b64Data = commaIdx !== -1 ? candidate.src.slice(commaIdx + 1) : '';
    const binary = atob(b64Data);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    note += ' (embedded base64)';
  } else {
    try {
      const res = await fetch(candidate.src);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = await res.arrayBuffer();
      bytes = new Uint8Array(buf);
      note += ` (${candidate.src.slice(0, 30)})`;
    } catch {
      bytes = generateFallbackPng(32, 32);
      note += ' (fallback generated)';
    }
  }

  return {
    index: candidate.index,
    bytes,
    note,
    srcStart: candidate.srcStart,
    srcEnd: candidate.srcEnd,
    tagStart: candidate.tagStart,
  };
}

/**
 * Parses safe insertion spots and existing attribute names inside an HTML tag.
 * @param {string} html
 * @param {number} tagStart
 * @returns {{ spots: number[], names: string[] }}
 */
export function parseTagAttributes(html, tagStart) {
  const tagEnd = html.indexOf('>', tagStart);
  if (tagEnd === -1) return { spots: [tagStart + 4], names: [] };

  const tagContent = html.slice(tagStart, tagEnd);
  const names = [];
  const spots = [];

  const tagNameMatch = /^<[a-zA-Z0-9_-]+/i.exec(tagContent);
  if (tagNameMatch) {
    spots.push(tagStart + tagNameMatch[0].length);
  }

  const attrRegex = /([a-zA-Z0-9_-]+)(?:\s*=\s*(?:["'][^"']*["']|[^\s>]+))?/g;
  let m;
  while ((m = attrRegex.exec(tagContent)) !== null) {
    if (m.index === 0) continue;
    names.push(m[1].toLowerCase());
    spots.push(tagStart + m.index + m[0].length);
  }

  let endSpot = tagEnd;
  if (html[endSpot - 1] === '/') endSpot--;
  spots.push(endSpot);

  return { spots, names };
}
