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
 * Computes sorted disjoint character spans [start, end) in HTML that should be
 * treated as opaque regions (comments, <script>, <style>, <textarea>, <title>).
 * Prevents HTML tag matchers from matching fake tags inside JS strings or comments.
 * @param {string} html
 * @returns {Array<{start: number, end: number}>}
 */
export function getHtmlMasks(html) {
  const raw = [];
  const patterns = [
    /<!--[\s\S]*?(?:-->|$)/g,
    /<script\b(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?(?:<\/script\s*>|$)/gi,
    /<style\b(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?(?:<\/style\s*>|$)/gi,
    /<textarea\b(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?(?:<\/textarea\s*>|$)/gi,
    /<title\b(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?(?:<\/title\s*>|$)/gi,
  ];
  for (const re of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(html)) !== null) {
      if (m[0].length === 0) break;
      raw.push({ start: m.index, end: m.index + m[0].length });
    }
  }
  if (!raw.length) return [];
  raw.sort((a, b) => a.start - b.start || a.end - b.end);
  const merged = [raw[0]];
  for (let i = 1; i < raw.length; i++) {
    const prev = merged[merged.length - 1];
    if (raw[i].start <= prev.end) {
      if (raw[i].end > prev.end) prev.end = raw[i].end;
    } else {
      merged.push(raw[i]);
    }
  }
  return merged;
}

function isInHtmlMask(masks, start, end) {
  for (let i = 0; i < masks.length; i++) {
    const m = masks[i];
    if (m.start >= end) break;
    if (start < m.end && end > m.start) return true;
  }
  return false;
}

function findUnmaskedMatches(html, regex, masks) {
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  const matches = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    if (!isInHtmlMask(masks, m.index, m.index + m[0].length)) {
      matches.push(m);
    }
    if (m[0].length === 0) re.lastIndex++;
  }
  return matches;
}

/**
 * Finds quote-aware closing '>' index for an HTML open tag starting at tagStart.
 * @param {string} html
 * @param {number} tagStart
 * @returns {number} index of '>' or -1
 */
function findTagClose(html, tagStart) {
  let inQuote = null;
  for (let i = tagStart + 1; i < html.length; i++) {
    const ch = html[i];
    if (inQuote) {
      if (ch === inQuote) inQuote = null;
    } else if (ch === '"' || ch === "'") {
      inQuote = ch;
    } else if (ch === '>') {
      return i;
    }
  }
  return -1;
}

/**
 * Strips occurrences of the original JS payload from inline <script> blocks in HTML.
 * Never alters visible HTML markup outside <script> tags.
 * @param {string} html
 * @param {string} js
 * @returns {string}
 */
export function stripOriginalJs(html, js) {
  if (!js || !js.trim()) return html;
  const trimmed = js.trim();
  const commentMasks = findUnmaskedMatches(html, /<!--[\s\S]*?(?:-->|$)/g, []);
  return html.replace(/<script\b((?:[^>"']|"[^"]*"|'[^']*')*)>([\s\S]*?)<\/script\s*>/gi, (match, attrs, scriptBody, offset) => {
    if (isInHtmlMask(commentMasks, offset, offset + match.length)) {
      return match;
    }
    if (/\bsrc\s*=/i.test(attrs)) {
      return match;
    }
    if (scriptBody.trim() === trimmed) {
      return '';
    }
    if (scriptBody.includes(trimmed)) {
      return `<script${attrs}>${scriptBody.replace(trimmed, '')}</script>`;
    }
    return match;
  });
}

/**
 * Injects payload before the closing </body>, </html>, or EOF, optionally allowing placement variation.
 * Uses HTML masking so strings like "</body>" inside <script> or comments are never targeted.
 * @param {string} html
 * @param {string} payload
 * @param {{ newline?: boolean, variation?: boolean, allowHead?: boolean, allowBodyStart?: boolean, allowBodyMid?: boolean, placement?: 'head'|'body-start'|'body-mid'|'body-end' }} options
 * @returns {string}
 */
export function injectBeforeClose(html, payload, options = {}) {
  const nl = options.newline === false ? '' : '\n';
  const block = `${nl}${payload}${nl}`;
  const masks = getHtmlMasks(html);

  const headCloses = findUnmaskedMatches(html, /<\/head\s*>/gi, masks);
  const bodyOpenStarts = findUnmaskedMatches(html, /<body\b/gi, masks);
  const bodyOpens = [];
  for (const bm of bodyOpenStarts) {
    const gt = findTagClose(html, bm.index);
    if (gt !== -1) bodyOpens.push({ index: bm.index, end: gt + 1 });
  }
  const bodyCloses = findUnmaskedMatches(html, /<\/body\s*>/gi, masks);
  const htmlCloses = findUnmaskedMatches(html, /<\/html\s*>/gi, masks);

  if (options.variation) {
    const candidates = [];
    if (options.allowHead && headCloses.length > 0) {
      candidates.push('head');
    }
    if (options.allowBodyStart !== false && bodyOpens.length > 0) {
      candidates.push('body-start');
    }
    if (options.allowBodyMid && bodyOpens.length > 0 && bodyCloses.length > 0) {
      const firstBodyStart = bodyOpens[0].end;
      const lastBodyClose = bodyCloses[bodyCloses.length - 1].index;
      const midMatches = findUnmaskedMatches(html, /<\/(?:header|nav|div|section|article|main)\s*>/gi, masks)
        .filter((m) => m.index >= firstBodyStart && m.index + m[0].length <= lastBodyClose);
      if (midMatches.length > 0) {
        candidates.push('body-mid');
      }
    }
    if (bodyCloses.length > 0) {
      candidates.push('body-end');
    }

    if (candidates.length > 0) {
      const chosen = options.placement || secureChoice(candidates);
      if (chosen === 'head' && headCloses.length > 0) {
        const idx = headCloses[0].index;
        return html.slice(0, idx) + block + html.slice(idx);
      }
      if (chosen === 'body-start' && bodyOpens.length > 0) {
        const idx = bodyOpens[0].end;
        return html.slice(0, idx) + block + html.slice(idx);
      }
      if (chosen === 'body-mid' && bodyOpens.length > 0 && bodyCloses.length > 0) {
        const firstBodyStart = bodyOpens[0].end;
        const lastBodyClose = bodyCloses[bodyCloses.length - 1].index;
        const midMatches = findUnmaskedMatches(html, /<\/(?:header|nav|div|section|article|main)\s*>/gi, masks)
          .filter((m) => m.index >= firstBodyStart && m.index + m[0].length <= lastBodyClose);
        if (midMatches.length > 0) {
          const pick = secureChoice(midMatches);
          const idx = pick.index + pick[0].length;
          return html.slice(0, idx) + block + html.slice(idx);
        }
      }
      if (chosen === 'body-end' && bodyCloses.length > 0) {
        const idx = bodyCloses[bodyCloses.length - 1].index;
        return html.slice(0, idx) + block + html.slice(idx);
      }
    }
  }

  if (bodyCloses.length > 0) {
    const idx = bodyCloses[bodyCloses.length - 1].index;
    return html.slice(0, idx) + block + html.slice(idx);
  }
  if (htmlCloses.length > 0) {
    const idx = htmlCloses[htmlCloses.length - 1].index;
    return html.slice(0, idx) + block + html.slice(idx);
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
 * Scans attributes inside a tag [tagStart, tagEnd) in a quote-aware manner.
 * @param {string} html
 * @param {number} tagStart
 * @param {number} tagEnd
 * @returns {Array<{name: string, nameLower: string, end: number, valStart?: number, valEnd?: number, value?: string}>}
 */
function scanTagAttributes(html, tagStart, tagEnd) {
  const attrs = [];
  let i = tagStart + 1;
  while (i < tagEnd - 1 && !/\s/.test(html[i]) && html[i] !== '/') i++;

  while (i < tagEnd - 1) {
    while (i < tagEnd - 1 && (/\s/.test(html[i]) || html[i] === '/')) i++;
    if (i >= tagEnd - 1) break;

    const nameStart = i;
    while (i < tagEnd - 1 && !/[\s=/>]/.test(html[i])) i++;
    const name = html.slice(nameStart, i);
    if (!name) { i++; continue; }

    let valStart;
    let valEnd;
    let value;
    let attrEnd = i;

    let j = i;
    while (j < tagEnd - 1 && /\s/.test(html[j])) j++;
    if (j < tagEnd - 1 && html[j] === '=') {
      j++;
      while (j < tagEnd - 1 && /\s/.test(html[j])) j++;
      if (j < tagEnd - 1 && (html[j] === '"' || html[j] === "'")) {
        const q = html[j];
        valStart = j + 1;
        j++;
        while (j < tagEnd - 1 && html[j] !== q) j++;
        valEnd = j;
        value = html.slice(valStart, valEnd);
        if (j < tagEnd - 1 && html[j] === q) j++;
        attrEnd = j;
      } else {
        valStart = j;
        while (j < tagEnd - 1 && !/\s/.test(html[j])) j++;
        if (j === tagEnd - 1 && html[j - 1] === '/') j--;
        valEnd = j;
        value = html.slice(valStart, valEnd);
        attrEnd = j;
      }
      i = attrEnd;
    }

    attrs.push({
      name,
      nameLower: name.toLowerCase(),
      end: attrEnd,
      valStart,
      valEnd,
      value,
    });
  }
  return attrs;
}

/**
 * Scans HTML for <img ...> elements and extracts positional spans of their src values.
 * Ignores <img> inside comments/scripts/styles/textareas, handles '>' inside quotes,
 * and matches exact 'src' attributes (ignoring data-src or quoted values).
 * @param {string} html
 * @returns {Array<{index: number, tag: string, tagStart: number, tagEnd: number, src: string, srcStart: number, srcEnd: number, isBase64: boolean}>}
 */
export function findImgTags(html) {
  const masks = getHtmlMasks(html);
  const imgStartRegex = /<img(?=\s|\/|>)/gi;
  const tags = [];
  let match;
  let domIndex = 0;

  while ((match = imgStartRegex.exec(html)) !== null) {
    const tagStart = match.index;
    const gt = findTagClose(html, tagStart);
    if (gt === -1) continue;
    const tagEnd = gt + 1;

    if (isInHtmlMask(masks, tagStart, tagEnd)) {
      imgStartRegex.lastIndex = tagEnd;
      continue;
    }

    const curDomIndex = domIndex++;
    const fullTag = html.slice(tagStart, tagEnd);
    const attrs = scanTagAttributes(html, tagStart, tagEnd);
    const srcAttr = attrs.find((a) => a.nameLower === 'src' && a.value !== undefined);

    if (srcAttr) {
      tags.push({
        index: curDomIndex,
        tag: fullTag,
        tagStart,
        tagEnd,
        src: srcAttr.value,
        srcStart: srcAttr.valStart,
        srcEnd: srcAttr.valEnd,
        isBase64: srcAttr.value.startsWith('data:'),
      });
    }

    imgStartRegex.lastIndex = tagEnd;
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
  const tagEnd = findTagClose(html, tagStart);
  if (tagEnd === -1) return { spots: [tagStart + 4], names: [] };

  const names = [];
  const spots = [];

  const tagNameMatch = /^<[\w-]+/i.exec(html.slice(tagStart, tagEnd));
  if (tagNameMatch) {
    spots.push(tagStart + tagNameMatch[0].length);
  }

  const attrs = scanTagAttributes(html, tagStart, tagEnd + 1);
  for (const attr of attrs) {
    names.push(attr.nameLower);
    spots.push(attr.end);
  }

  let endSpot = tagEnd;
  if (html[endSpot - 1] === '/') endSpot--;
  spots.push(endSpot);

  return { spots, names };
}



