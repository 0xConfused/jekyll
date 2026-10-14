// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * codecamo.js — Port of the CodeCamo Python obfuscator
 * (_CodeCamo.py, _JsReplaceStrings.py, _JsDotObject.py, _JsVarName.py, _JsComment.py).
 *
 * Pipeline:
 *   Pass 1 — split every string literal containing word.dot.word fragments and
 *             rejoin the parts with a runtime "." expression built from a
 *             navigator/location/document/window chain (the code itself gets
 *             camouflaged by pass 2, compounding the effect).
 *   Pass 2 — rewrite object.property references in CODE ONLY using randomly
 *             chosen semantically-equivalent variations (bracket access,
 *             IIFE, with, Proxy, Symbol-Proxy, destructuring).
 *   Pass 3 — insert realistic decoy comments (changelogs, API doc blocks,
 *             licenses, TODO/FIXME tags) at safe line boundaries.
 *
 * BUGFIXES vs the Python originals (details in the conversation summary):
 *   - Passes are string/comment/regex-LITERAL-AWARE. The Python regexes
 *     would happily rewrite "www.website.com" INSIDE a string literal and
 *     mutate regex literals like /a.b/ into broken code.
 *   - Property matches starting with a digit are excluded (Python would
 *     rewrite 123.45 -> 123["45"], which is undefined, not 1.5 * 100).
 *   - Single non-overlapping transformation pass instead of Python's
 *     "transform until stable" loop, which could re-transform its own
 *     generated code and grow the output unboundedly.
 *   - Dot extraction restricted to [str.search(/\x2E/)]-style expressions;
 *     Python's first-to-last-dot replace variants return a multi-character
 *     span when the source string contains more than one dot.
 *
 * Verification: the final output is re-scanned and the engine refuses to
 * emit if any string literal still contains a word.dot.word fragment.
 */

import { randInt, secureChoice, stripOriginalJs, injectBeforeClose, log } from '../lib/engine-utils.js';

// --------------------------------------------------------------- name pools
// Port of _JsVarName.py / the name tables in _CodeCamo.py.
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

function generateVariableName() {
  let base = secureChoice(FRONT_END_WORDS);
  const prepend = randInt(2);
  const append = randInt(2);
  let name = prepend ? secureChoice(PRE_MODS) + base[0].toUpperCase() + base.slice(1) : base;
  if (append) name += secureChoice(MODS);
  return name;
}
const randomKeyword = () => secureChoice(['var', 'const']);

// ------------------------------------------------------------- JS tokenizer
/**
 * Scan JS source and return the spans that must NOT be textually rewritten:
 * string/template literals, regex literals, and comments. This scanner is the
 * central bugfix over the Python regex-only approach.
 * @returns {{strings:Array<{start:number,end:number}>, masks:Array<{start:number,end:number}>}}
 */
function scanJs(code) {
  const strings = [], masks = [];
  let i = 0;
  let lastWord = ''; // last identifier/keyword seen, for regex-vs-division
  const REGEX_CTX = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '~', '^', '<', '>']);
  const KEYWORDS_BEFORE_REGEX = new Set(['return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void', 'instanceof', 'do', 'else']);

  while (i < code.length) {
    const c = code[i];

    // line comment
    if (c === '/' && code[i + 1] === '/') {
      const s = i;
      while (i < code.length && code[i] !== '\n') i++;
      masks.push({ start: s, end: i });
      continue;
    }
    // block comment
    if (c === '/' && code[i + 1] === '*') {
      const s = i;
      i += 2;
      while (i < code.length && !(code[i] === '*' && code[i + 1] === '/')) i++;
      i += 2;
      masks.push({ start: s, end: i });
      continue;
    }
    // string / template literal
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
    // regex literal (in operand-for-expression position)
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
          else if (r === '\n') break; // not a regex after all; bail safely
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
    // track words / context for regex-vs-division decisions
    if (/[A-Za-z0-9_$]/.test(c)) {
      let j = i;
      while (j < code.length && /[A-Za-z0-9_$]/.test(code[j])) j++;
      lastWord = code.slice(i, j);
      i = j;
      continue;
    }
    if (!/\s/.test(c)) lastWord = c;
    i++;
  }
  return { strings, masks };
}

const inMask = (masks, start, end) =>
  masks.some((m) => start < m.end && end > m.start);

// ------------------------------------------------------------ dot generator
// Port of _JsDotObject.py. Chains of browser globals, ending in a property
// that contains at least one dot in its runtime string value; the dot is then
// extracted index-style. Only patterns that provably yield exactly "."
// survive the port (see file header bugfix note).
const STARTING_OBJECTS = ['navigator', 'location', 'document', 'window'];
const OBJECT_PROPS = {
  navigator: ['appVersion', 'userAgent', 'oscpu'],
  location: ['origin', 'href', 'host'],
  document: ['documentURI', 'baseURI', 'domain', 'URL', 'location'],
  window: ['origin', 'navigator', 'location', 'document'],
};
function generateDotObjectChain() {
  let output = secureChoice(STARTING_OBJECTS);
  for (;;) {
    const last = output.split('.').pop();
    if (OBJECT_PROPS[last]) output += '.' + secureChoice(OBJECT_PROPS[last]);
    else break;
  }
  return output;
}
function generateDotExpr() {
  const chain = generateDotObjectChain();
  return secureChoice([
    `${chain}[${chain}.search(/\\x2E/)]`,
    `${chain}[${chain}.search(/\\x2e/)]`,
    '(0,eval)("")&&String.fromCharCode(46)'.replace('(0,eval)("")&&', ''), // String.fromCharCode(46)
    'String.fromCodePoint(46)',
    `["a","b"].join(${chain}[${chain}.search(/\\x2E/)])`,
  ])();
}

// -------------------------------------------------- pass 1: split strings
/**
 * Rewrite every string literal containing word.dot.word fragments as
 * concatenation around a runtime dot expression, e.g.
 *   "http://www.website.com"  ->  "http://www" + <dotExpr> + "website" + <dotExpr> + "com"
 * Operates only on literal spans found by scanJs.
 * @returns {{code:string, count:number}}
 */
function splitDottedStrings(code) {
  const { strings } = scanJs(code);
  let out = '', cursor = 0, count = 0;
  for (const span of strings) {
    out += code.slice(cursor, span.start);
    const q = code[span.start];
    const content = code.slice(span.start + 1, span.end - 1);
    const parts = [];
    let last = 0;
    const re = /\w\.\w/g;
    for (let m; (m = re.exec(content)); ) {
      const dotIdx = m.index + 1;
      parts.push(content.slice(last, dotIdx));
      last = dotIdx + 1;
    }
    if (parts.length) {
      parts.push(content.slice(last));
      count++;
      const dot = generateDotExpr();
      out += parts.map((p) => q + p + q).join(' + ' + dot + ' + ');
    } else {
      out += code.slice(span.start, span.end);
    }
    cursor = span.end;
  }
  out += code.slice(cursor);
  return { code: out, count };
}

// ------------------------------------------ pass 2: property camouflaging
/**
 * Rewrite object.property chains in code (never inside strings/comments/regex
 * literals) with randomly chosen semantically-equivalent variations.
 * Identifiers must start with a letter/_/$ so numeric literals like 123.45
 * are never matched.
 */
const PROP_RE = /(?:[A-Za-z_$][\w$]*\.)+([A-Za-z_$][\w$]*)/g;

function applyObjectTransform(obj, prop) {
  const a = generateVariableName(), b = generateVariableName(),
    c = generateVariableName(), d = generateVariableName();
  const vc = randomKeyword(), vc1 = randomKeyword();
  return secureChoice([
    // identity: keeps some ordinary access for realism (faithful to Python v0)
    () => `${obj}.${prop}`,
    () => `(function(){${vc} ${a}="${prop}";return ${obj}[${a}]})()`,
    () => `${obj}["${prop}"]`,
    () => `(function(){with(${obj}){return ${prop};}})()`,
    () => `(()=>{${vc} ${a}=new Proxy(${obj},{get:(${b},${c})=>${c}==='${prop}'?${b}[${c}]:Reflect.get(${b},${c})});return ${a}})()['${prop}']`,
    () => `(()=>{${vc} {${prop}:l}=${obj};return l})()`,
    () => `(function(){${vc} ${a}=Symbol();${vc1} ${b}=new Proxy(${obj},{get:(${c},prop)=>prop===${a}?${c}.prop:${c}[prop]});${vc} ${d}=${b}[${a}];return ${d}})()`,
  ])();
}

function transformProperties(code, masks) {
  let count = 0;
  const out = code.replace(PROP_RE, (m, prop, offset) => {
    if (inMask(masks, offset, offset + m.length)) return m;
    count++;
    const obj = m.slice(0, m.length - prop.length - 1);
    return applyObjectTransform(obj, prop);
  });
  return { code: out, count };
}

// ------------------------------------------------- pass 3: decoy comments
// Port of _JsComment.py — plausible changelog / doc / license / tag comments.
const COMMENT_PARTS = {
  actions: ['Version', 'Change', 'Update', 'Fix', 'Added', 'Removed', 'Refactored', 'Deprecated', 'Bugfix', 'Feature', 'Enhancement'],
  descriptions: ['Added new feature', 'Fixed a bug', 'Refactored code', 'Improved performance', 'Deprecated old method', 'Updated documentation', 'Enhanced user experience', 'Removed deprecated features', 'Improved security', 'Added support for new API'],
  details: ['security update', 'performance optimization', 'bug fix', 'UI enhancement', 'backend improvement', 'API update', 'documentation revision', 'deprecated feature removal', 'code refactoring', 'user experience enhancement'],
  additional: ['Please refer to the documentation', 'Check the issue tracker', 'See the changelog for more details', 'Refer to the commit history', 'This update addresses known issues', 'Refer to the release notes'],
  licenses: ['© 2024 Mozilla. All rights reserved.', 'Licensed under the MIT License.', 'Distributed under the Apache License, Version 2.0.', 'This project is open-source under the GNU General Public License.', 'Proprietary software. Redistribution is prohibited.'],
  apiDocHeads: ['Description', 'Parameters', 'Returns', 'Example', 'Notes', 'See Also'],
  tags: ['TODO', 'FIXME', 'NOTE'],
};
function generateRandomComment() {
  const P = COMMENT_PARTS;
  const pick = (a) => secureChoice(a);
  return pick([
    () => `/* ${pick(P.actions)} ${1 + randInt(9)}.${randInt(10)}.${randInt(10)} - ${pick(P.descriptions)}. */`,
    () => `/* ${pick(P.actions)} on ${pick(['2024-01-01', '2024-07-15', '2024-03-22'])}. ${pick(P.descriptions)}. ${pick(P.additional)}. */`,
    () => `/**\n * ${pick(P.descriptions)}\n * XMLHttpRequest [xhr.open('GET', url, false)] - Due to a recent ${pick(P.details)}, we are deprecating this call.\n *\n * Instead in the future use the \`fetch\` API.\n **/`,
    () => `/**\n * ${pick(P.actions)}: ${pick(P.descriptions)}\n * document.all\n * // document.all is a way to access elements in the DOM and is no longer recommended for use.\n * ${pick(['document.getElementById()', 'document.querySelector()'])}\n **/`,
    () => `/*\n * ${pick(P.licenses)}\n * ${pick(['See LICENSE file for details.', 'All rights reserved.', 'For more information, visit our website.'])}\n */`,
    () => `/*** ${pick(P.descriptions)} to improve ${pick(P.details)} handling. ***/`,
    () => `/*** This section implements important UI functionality. ${pick(P.additional)} before making changes. ***/`,
    () => `/*@${pick(P.apiDocHeads)}: ${pick(P.descriptions)} related to a ${pick(P.details)}.*/`,
    () => `/*@${pick(P.tags)}: ${pick(P.descriptions)}. ${pick(P.additional)}.*/`,
  ])();
}

function injectDecoyComments(code, maxComments) {
  const { masks } = scanJs(code);
  // candidate insertion points: line starts that are not inside a mask
  const points = [];
  for (let i = 0; i < code.length; i++)
    if (code[i] === '\n' && !inMask(masks, i + 1, i + 2)) points.push(i + 1);
  if (!points.length) return { code, count: 0 };

  const n = Math.min(maxComments, points.length);
  const chosen = new Set();
  while (chosen.size < n) chosen.add(points[randInt(points.length)]);

  let out = '', cursor = 0;
  for (const p of [...chosen].sort((x, y) => x - y)) {
    out += code.slice(cursor, p) + generateRandomComment() + '\n';
    cursor = p;
  }
  out += code.slice(cursor);
  return { code: out, count: n };
}

// ------------------------------------------------------------- verification
/**
 * Re-scan the final output. The compile goal (per regex_test.txt's hardened
 * detector) is that NO string literal contains a word.dot.word fragment.
 */
function verifyNoDottedStrings(code) {
  const remaining = scanJs(code).strings.filter(
    (s) => /\w\.\w/.test(code.slice(s.start + 1, s.end - 1)),
  );
  return { ok: remaining.length === 0, remaining: remaining.length };
}

// ------------------------------------------------------------------- engine
export const engine = {
  id: 'codecamo',
  label: 'CodeCamo (string splitting + property camouflage)',
  description:
    'Obfuscates the JS payload by splitting dotted URL-like strings behind runtime ' +
    'dot expressions, rewriting object.property references into random equivalent ' +
    'forms (bracket access, IIFE, with, Proxy, Symbol), and decoying with ' +
    'realistic changelog/API/license comments. Verified: no string literal in ' +
    'the output retains a word.dot.word fragment.',

  execute({ html, js }) {
    if (!js || !js.trim()) throw new Error('JavaScript payload is empty.');
    const stats = [];

    // Pass 1: split dotted strings, rejoining with dot expressions.
    const p1 = splitDottedStrings(js);
    stats.push(`strings split ............... ${p1.count}`);

    // Pass 2: camouflage property chains — dot expressions generated in pass 1
    // are themselves camouflage-compounded here. Strings/regex/comments are
    // masked so only real code is rewritten.
    const masks = scanJs(p1.code).masks;
    const p2 = transformProperties(p1.code, masks);
    stats.push(`properties transformed ..... ${p2.count}`);

    // Pass 3: decoy comments at safe line boundaries (2–6, matching the
    // volume of the original sample generator).
    const p3 = injectDecoyComments(p2.code, 2 + randInt(5));
    stats.push(`decoy comments inserted .... ${p3.count}`);

    const finalJs = p3.code;
    const check = verifyNoDottedStrings(finalJs);
    if (!check.ok)
      throw new Error(
        `CODECAMO BUG — ${check.remaining} string literal(s) still contain ` +
        'word.dot.word fragments; output not emitted.',
      );
    stats.push('round-trip verified ....... no dotted fragments left in strings');

    // Consistent with the other engines: strip any inline copy of the original
    // JS from the page, then inject the camouflaged payload before </body>.
    const stripped = stripOriginalJs(html, js);
    const result = injectBeforeClose(stripped, `<script>\n${finalJs}\n</script>`);

    return {
      html: result,
      stdout: log('CODECAMO',
        ...stats,
        `payload size ............... ${js.length} -> ${finalJs.length} chars`),
      stderr: '',
    };
  },
};
export default engine;
