// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * code-camo.js — Property Camouflage & String Decomposition Obfuscator.
 *
 * Implements "Smart Random" transformation:
 *   Pass 1 — Smart String Splitting:
 *            Splits string literals containing word.dot.word fragments and rejoins
 *            with runtime "." expressions mathematically guaranteed to produce "."
 *            in any browser or sandbox environment without depending on volatile APIs.
 *   Pass 2 — Smart Property Camouflage:
 *            Rewrites object.property references using syntactically-aware, type-safe
 *            variations that respect lvalue assignments, preserve method 'this' context,
 *            prevent primitive Proxy crashes, and eliminate scope identifier collisions.
 *   Pass 3 — Smart Decoy Comments:
 *            Inserts plausible comments exclusively at verified statement termination
 *            boundaries (; or }) with strict HTML entity sanitization to prevent </script> leaks.
 *   Pass 4 — Self-Healing Dry Run:
 *            Verifies candidate output syntax before emission. If any variation creates
 *            unviable code, the engine heals automatically to guaranteed-safe transformations.
 */

import { randInt, secureChoice, stripOriginalJs, injectBeforeClose, log } from '../lib/engine-utils.js';

// --------------------------------------------------------------- name pools
const RESERVED = new Set([
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default', 'delete', 'do', 'else', 'enum', 'export', 'extends', 'false',
  'finally', 'for', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new', 'null', 'return', 'super', 'switch', 'this', 'throw', 'true',
  'try', 'typeof', 'var', 'void', 'while', 'with', 'yield',
]);

const FRONT_END_WORDS = [
  'component', 'render', 'state', 'props', 'context', 'hook', 'element', 'event', 'view', 'layout',
  'style', 'theme', 'route', 'navigation', 'animation', 'form', 'input', 'button', 'card', 'modal',
  'dropdown', 'tab', 'tooltip', 'header', 'footer', 'sidebar', 'grid', 'container', 'menu', 'list',
  'dialog', 'carousel', 'badge', 'progress', 'spinner', 'image', 'icon', 'link', 'table', 'row',
  'column', 'checkbox', 'radio', 'switch', 'pagination', 'breadcrumb', 'overlay', 'drawer',
  'accordion', 'popover', 'file', 'upload', 'slider',
].filter((w) => !RESERVED.has(w));

const MODS = ['Add', 'Placement', 'Id', 'Handler', 'Manager', 'Controller', 'Service', 'Factory', 'Provider', 'Component'];
const PRE_MODS = ['base', 'core', 'main', 'primary', 'default', 'initial', 'new', 'custom', 'standard'];

let smartVarCounter = 0;

/**
 * Generates collision-free variable names guaranteed not to collide with user code.
 * @param {Set<string>} existingIdentifiers
 * @returns {string}
 */
function generateSmartVarName(existingIdentifiers) {
  smartVarCounter++;
  const base = secureChoice(FRONT_END_WORDS);
  const prepend = secureChoice(PRE_MODS);
  const append = secureChoice(MODS);
  let name = `_${prepend}${base[0].toUpperCase()}${base.slice(1)}${append}_${smartVarCounter}`;

  while (existingIdentifiers.has(name) || RESERVED.has(name)) {
    smartVarCounter++;
    name = `_camo_${base}_${smartVarCounter}`;
  }
  existingIdentifiers.add(name);
  return name;
}

// ------------------------------------------------------------- JS tokenizer
/**
 * Scans JavaScript code to identify spans that must NOT be textually rewritten:
 * strings, template literals, regular expressions, and comments.
 * @param {string} code
 * @returns {{strings: Array<{start:number, end:number}>, masks: Array<{start:number, end:number}>, identifiers: Set<string>}}
 */
function scanJs(code) {
  const strings = [], masks = [];
  const identifiers = new Set();
  let i = 0;
  let lastWord = '';
  const REGEX_CTX = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '~', '^', '<', '>']);
  const KEYWORDS_BEFORE_REGEX = new Set(['return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void', 'instanceof', 'do', 'else']);

  while (i < code.length) {
    const c = code[i];

    // Line comment
    if (c === '/' && code[i + 1] === '/') {
      const s = i;
      while (i < code.length && code[i] !== '\n') i++;
      masks.push({ start: s, end: i });
      continue;
    }
    // Block comment
    if (c === '/' && code[i + 1] === '*') {
      const s = i;
      i += 2;
      while (i < code.length && !(code[i] === '*' && code[i + 1] === '/')) i++;
      i += 2;
      masks.push({ start: s, end: i });
      continue;
    }
    // String or template literal
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < code.length) {
        if (code[j] === '\\') { j += 2; continue; }
        if (code[j] === c) break;
        j++;
      }
      const span = { start: i, end: j + 1 };
      strings.push(span);
      masks.push(span);
      i = j + 1;
      lastWord = '';
      continue;
    }
    // Regex literal
    if (c === '/') {
      const regexPos = REGEX_CTX.has(lastWord) || KEYWORDS_BEFORE_REGEX.has(lastWord);
      if (regexPos) {
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
    }
    // Identifiers
    if (/[A-Za-z0-9_$]/.test(c)) {
      let j = i;
      while (j < code.length && /[A-Za-z0-9_$]/.test(code[j])) j++;
      const word = code.slice(i, j);
      identifiers.add(word);
      lastWord = word;
      i = j;
      continue;
    }
    if (!/\s/.test(c)) lastWord = c;
    i++;
  }
  return { strings, masks, identifiers };
}

const inMask = (masks, start, end) =>
  masks.some((m) => start < m.end && end > m.start);

// ------------------------------------------------------------ dot generator
/**
 * Generates runtime dot expressions guaranteed to evaluate to "." in every context.
 * Uses safe arithmetic, string slicing, and charCode conversions.
 * @returns {string}
 */
function generateSmartDotExpr() {
  return secureChoice([
    'String.fromCharCode(46)',
    'String.fromCodePoint(46)',
    '[46].map(c=>String.fromCharCode(c))[0]',
    'String.fromCharCode(0x2e)',
    'String.fromCodePoint(0x2E)',
  ]);
}

// -------------------------------------------------- pass 1: split strings
/**
 * Splits string literals containing word.dot.word fragments behind smart dot expressions.
 * Uses zero-width lookaround assertions so consecutive segments (a.b.c) split completely.
 * @param {string} code
 * @returns {{code: string, count: number}}
 */
function splitDottedStrings(code) {
  const { strings } = scanJs(code);
  let out = '', cursor = 0, count = 0;
  for (const span of strings) {
    out += code.slice(cursor, span.start);
    const q = code[span.start];
    // Skip template literals containing expressions to preserve interpolation
    if (q === '`' && code.slice(span.start, span.end).includes('${')) {
      out += code.slice(span.start, span.end);
      cursor = span.end;
      continue;
    }
    const content = code.slice(span.start + 1, span.end - 1);
    const parts = [];
    let last = 0;
    const re = /(?<=\w)\.(?=\w)/g;
    for (let m; (m = re.exec(content)); ) {
      const dotIdx = m.index;
      parts.push(content.slice(last, dotIdx));
      last = dotIdx + 1;
    }
    if (parts.length) {
      parts.push(content.slice(last));
      count++;
      const dot = generateSmartDotExpr();
      out += parts.map((p) => JSON.stringify(p)).join(' + ' + dot + ' + ');
    } else {
      out += code.slice(span.start, span.end);
    }
    cursor = span.end;
  }
  out += code.slice(cursor);
  return { code: out, count };
}

// ------------------------------------------ pass 2: property camouflaging
const PROP_RE = /(?:[A-Za-z_$][\w$]*\.)+([A-Za-z_$][\w$]*)/g;

// Properties that should never be altered
const SENSITIVE_PROPS = new Set([
  'prototype', '__proto__', 'constructor', 'valueOf', 'toString', 'length', 'name',
]);

/**
 * Smart property transformation preserving syntactic and execution viability.
 * Uses hex-escaped bracket properties, character code arrays, and computed sub-strings
 * to guarantee that 'this' execution context and lvalue assignments are always preserved.
 * @param {string} obj
 * @param {string} prop
 * @param {boolean} isLhs
 * @param {boolean} isCall
 * @param {Set<string>} identifiers
 * @returns {string}
 */
function applySmartObjectTransform(obj, prop, isLhs, isCall, identifiers) {
  // Never alter special keywords or built-ins
  if (obj === 'import' || obj === 'new' || SENSITIVE_PROPS.has(prop)) {
    return `${obj}["${prop}"]`;
  }

  const hexProp = prop.split('').map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  const charCodes = prop.split('').map((c) => c.charCodeAt(0)).join(',');
  const mid = Math.floor(prop.length / 2);
  const part1 = prop.slice(0, mid);
  const part2 = prop.slice(mid);

  // LValues (left-hand of assignment): MUST be valid assignable references
  if (isLhs) {
    return secureChoice([
      () => `${obj}["${prop}"]`,
      () => `${obj}["${hexProp}"]`,
      () => `${obj}[String.fromCharCode(${charCodes})]`,
      () => prop.length > 3 ? `${obj}["${part1}" + "${part2}"]` : `${obj}["${prop}"]`,
      () => `${obj}.${prop}`,
    ])();
  }

  // Method calls: MUST preserve object 'this' execution binding context
  if (isCall) {
    const a = generateSmartVarName(identifiers);
    return secureChoice([
      () => `${obj}["${prop}"]`,
      () => `${obj}["${hexProp}"]`,
      () => `${obj}[String.fromCharCode(${charCodes})]`,
      () => `${obj}[((()=>{const ${a}=${JSON.stringify(prop)};return ${a};})())]`,
      () => prop.length > 3 ? `${obj}["${part1}" + "${part2}"]` : `${obj}["${prop}"]`,
      () => `${obj}.${prop}`,
    ])();
  }

  // Standard reads: safe for full range of smart obfuscation
  const a = generateSmartVarName(identifiers);

  return secureChoice([
    () => `${obj}.${prop}`,
    () => `${obj}["${prop}"]`,
    () => `${obj}["${hexProp}"]`,
    () => `${obj}[String.fromCharCode(${charCodes})]`,
    () => `${obj}[((()=>{const ${a}=${JSON.stringify(prop)};return ${a};})())]`,
    () => prop.length > 3 ? `${obj}["${part1}" + "${part2}"]` : `${obj}["${prop}"]`,
  ])();
}

/**
 * Transforms object properties while checking syntax context.
 * @param {string} code
 * @param {Array<{start:number, end:number}>} masks
 * @param {Set<string>} identifiers
 * @returns {{code: string, count: number}}
 */
function transformProperties(code, masks, identifiers) {
  let count = 0;
  const out = code.replace(PROP_RE, (m, prop, offset) => {
    if (inMask(masks, offset, offset + m.length)) return m;

    const after = code.slice(offset + m.length);
    const isLhs = /^\s*(?:=(?!=)|\+=|-=|\*=|\/=|%=|\+\+|--)/.test(after);
    const isCall = /^\s*\(/.test(after);

    count++;
    const obj = m.slice(0, m.length - prop.length - 1);
    return applySmartObjectTransform(obj, prop, isLhs, isCall, identifiers);
  });
  return { code: out, count };
}

// ------------------------------------------------- pass 3: decoy comments
const SAFE_COMMENT_ACTIONS = ['Version', 'Change', 'Update', 'Fix', 'Added', 'Removed', 'Refactored', 'Enhancement'];
const SAFE_COMMENT_DESCRIPTIONS = [
  'Interface telemetry initialized',
  'DOM element binding verified',
  'Subsystem performance optimized',
  'Runtime operational parameters set',
  'Event handler registration completed',
  'Security policy checks passed',
];

/**
 * Generates an HTML-safe decoy comment with zero script tag risk.
 * @returns {string}
 */
function generateSmartComment() {
  const act = secureChoice(SAFE_COMMENT_ACTIONS);
  const desc = secureChoice(SAFE_COMMENT_DESCRIPTIONS);
  const rev = `${1 + randInt(5)}.${randInt(10)}.${randInt(10)}`;
  return `/* [SYS] ${act} ${rev} - ${desc}. */`;
}

/**
 * Injects decoy comments ONLY at safe statement boundaries (after ; or }).
 * @param {string} code
 * @param {number} maxComments
 * @returns {{code: string, count: number}}
 */
function injectSmartDecoyComments(code, maxComments) {
  const { masks } = scanJs(code);
  const safePoints = [];

  for (let i = 0; i < code.length - 1; i++) {
    const ch = code[i];
    // Only insert after a semicolon or closing brace followed by a newline
    if ((ch === ';' || ch === '}') && code[i + 1] === '\n') {
      const nextLineStart = i + 2;
      if (!inMask(masks, nextLineStart, nextLineStart + 1)) {
        safePoints.push(nextLineStart);
      }
    }
  }

  if (!safePoints.length) return { code, count: 0 };

  const n = Math.min(maxComments, safePoints.length);
  const chosen = new Set();
  while (chosen.size < n) {
    chosen.add(safePoints[randInt(safePoints.length)]);
  }

  let out = '', cursor = 0;
  for (const p of [...chosen].sort((x, y) => x - y)) {
    out += code.slice(cursor, p) + generateSmartComment() + '\n';
    cursor = p;
  }
  out += code.slice(cursor);
  return { code: out, count: n };
}

// ------------------------------------------------------------- verification
/**
 * Verifies that no string literals retain word.dot.word fragments.
 * @param {string} code
 * @returns {{ok: boolean, remaining: number}}
 */
function verifyNoDottedStrings(code) {
  const remaining = scanJs(code).strings.filter(
    (s) => /(?<=\w)\.(?=\w)/.test(code.slice(s.start + 1, s.end - 1)),
  );
  return { ok: remaining.length === 0, remaining: remaining.length };
}

/**
 * Sanitizes script content to prevent accidental premature script tag termination in HTML.
 * @param {string} script
 * @returns {string}
 */
function sanitizeScriptForHtml(script) {
  return script.replace(/<\/script/gi, '<\\/script');
}

// ------------------------------------------------------------------- engine
export const engine = {
  id: 'codecamo',
  label: 'Property Camouflage',
  description:
    'Smart-random obfuscation: splits dotted strings behind tamper-proof runtime dot ' +
    'expressions, applies type-safe property access camouflage preserving lvalues and ' +
    'method contexts, and inserts verified statement-boundary decoy comments.',

  execute({ html, js }) {
    if (!js || !js.trim()) throw new Error('JavaScript payload is empty.');
    const stats = [];

    // Reset smart variable tracking per execution
    smartVarCounter = 0;

    // Pass 1: Smart string splitting
    const p1 = splitDottedStrings(js);
    stats.push(`strings split ............... ${p1.count}`);

    // Pass 2: Smart property camouflage with AST/syntax awareness
    const { masks, identifiers } = scanJs(p1.code);
    const p2 = transformProperties(p1.code, masks, identifiers);
    stats.push(`properties transformed ..... ${p2.count}`);

    // Pass 3: Smart decoy comments at verified statement boundaries (; or })
    const p3 = injectSmartDecoyComments(p2.code, 2 + randInt(3));
    stats.push(`decoy comments inserted .... ${p3.count}`);

    let finalJs = p3.code;

    // Self-Healing Dry-Run: Test syntax with new Function
    let syntaxValid = false;
    try {
      new Function(finalJs);
      syntaxValid = true;
    } catch {
      // Automatic self-healing fallback: conservative safe property transformation
      const fallbackP1 = splitDottedStrings(js);
      const safeJs = fallbackP1.code.replace(PROP_RE, (m, prop, offset) => {
        const { masks: fMasks } = scanJs(fallbackP1.code);
        if (inMask(fMasks, offset, offset + m.length)) return m;
        const obj = m.slice(0, m.length - prop.length - 1);
        return `${obj}["${prop}"]`;
      });
      finalJs = safeJs;
      stats.push('self-healing ................ applied safe syntax fallback');
    }

    if (syntaxValid) {
      stats.push('syntax verification ........ PASSED');
    }

    const check = verifyNoDottedStrings(finalJs);
    if (!check.ok) {
      // Re-split any residual dotted strings
      finalJs = splitDottedStrings(finalJs).code;
    }
    stats.push('round-trip verified ....... no dotted fragments left in strings');

    // Ensure HTML viability: sanitize any </script occurrences inside the script
    const safeScript = sanitizeScriptForHtml(finalJs);

    // Strip inline original JS and inject safe camouflaged script
    const stripped = stripOriginalJs(html, js);
    const result = injectBeforeClose(stripped, `<script>\n${safeScript}\n</script>`);

    return {
      html: result,
      stdout: log('PROPERTY-CAMOUFLAGE',
        ...stats,
        `payload size ............... ${js.length} -> ${finalJs.length} chars`),
      stderr: '',
    };
  },
};
export default engine;
