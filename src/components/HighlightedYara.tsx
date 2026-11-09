// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';

export interface YaraToken {
  type:
    | 'comment'
    | 'section'
    | 'keyword'
    | 'modifier'
    | 'rule-name'
    | 'variable'
    | 'regex'
    | 'string'
    | 'hex-string'
    | 'number'
    | 'operator'
    | 'punctuation'
    | 'plain';
  text: string;
}

const YARA_KEYWORDS = new Set([
  'rule',
  'meta',
  'strings',
  'condition',
  'all',
  'any',
  'none',
  'of',
  'them',
  'and',
  'or',
  'not',
  'filesize',
  'for',
  'in',
  'at',
  'entrypoint',
  'contains',
  'matches',
  'startswith',
  'endswith',
  'icontains',
  'iequals',
  'istartswith',
  'iendswith',
  'int8',
  'int16',
  'int32',
  'uint8',
  'uint16',
  'uint32',
  'int8be',
  'int16be',
  'int32be',
  'uint8be',
  'uint16be',
  'uint32be',
]);

const YARA_MODIFIERS = new Set([
  'nocase',
  'ascii',
  'wide',
  'fullword',
  'private',
  'global',
]);

const YARA_SECTIONS = new Set(['meta:', 'strings:', 'condition:']);

/**
 * Tokenizes a single line of YARA code for accurate syntax highlighting.
 */
export function tokenizeYaraLine(line: string): YaraToken[] {
  const tokens: YaraToken[] = [];
  let i = 0;
  const len = line.length;

  while (i < len) {
    // 1. Line comments
    if (line.startsWith('//', i)) {
      tokens.push({ type: 'comment', text: line.slice(i) });
      break;
    }
    if (line.startsWith('/*', i)) {
      const end = line.indexOf('*/', i);
      const comment = end === -1 ? line.slice(i) : line.slice(i, end + 2);
      tokens.push({ type: 'comment', text: comment });
      i += comment.length;
      continue;
    }

    // 2. Whitespace
    const wsMatch = line.slice(i).match(/^\s+/);
    if (wsMatch) {
      tokens.push({ type: 'plain', text: wsMatch[0] });
      i += wsMatch[0].length;
      continue;
    }

    // 3. Section Headers (meta:, strings:, condition:)
    const sectionMatch = line.slice(i).match(/^(meta|strings|condition):/);
    if (sectionMatch) {
      tokens.push({ type: 'section', text: sectionMatch[0] });
      i += sectionMatch[0].length;
      continue;
    }

    // 4. Variables ($var, $*, #var, @var, !var)
    if ('$#@!'.includes(line[i])) {
      const varMatch = line.slice(i).match(/^[$#@!][a-zA-Z0-9_*]*/);
      if (varMatch && varMatch[0].length > 0) {
        tokens.push({ type: 'variable', text: varMatch[0] });
        i += varMatch[0].length;
        continue;
      }
    }

    // 5. Strings: Double or Single Quoted
    if (line[i] === '"' || line[i] === "'") {
      const quote = line[i];
      let j = i + 1;
      while (j < len && line[j] !== quote) {
        if (line[j] === '\\') j++; // skip escaped char
        j++;
      }
      if (j < len) j++; // include closing quote
      tokens.push({ type: 'string', text: line.slice(i, j) });
      i = j;
      continue;
    }

    // 6. Regular Expression: /.../[flags]
    // In YARA strings section: occurs after = /.../ or in condition expressions
    if (line[i] === '/') {
      let j = i + 1;
      let escaped = false;
      while (j < len) {
        if (escaped) {
          escaped = false;
        } else if (line[j] === '\\') {
          escaped = true;
        } else if (line[j] === '/') {
          j++;
          break;
        }
        j++;
      }
      // Consume any trailing flags (e.g. i, s)
      while (j < len && /[a-z]/i.test(line[j])) {
        j++;
      }
      tokens.push({ type: 'regex', text: line.slice(i, j) });
      i = j;
      continue;
    }

    // 7. Hex String: { E2 34 ?? A1 }
    if (line[i] === '{' && line.includes('}')) {
      const closing = line.indexOf('}', i);
      const inner = line.slice(i + 1, closing).trim();
      // Check if it looks like a YARA hex pattern
      if (/^[0-9a-fA-F\s?~|()-]+$/.test(inner) && inner.length > 0) {
        tokens.push({ type: 'hex-string', text: line.slice(i, closing + 1) });
        i = closing + 1;
        continue;
      }
    }

    // 8. Numbers (Hex: 0x..., Decimals: 1000000, Sizes: 25MB, 100KB)
    const numMatch = line.slice(i).match(/^(?:0x[0-9a-fA-F]+|\d+(?:[KMGT]B)?)\b/);
    if (numMatch) {
      tokens.push({ type: 'number', text: numMatch[0] });
      i += numMatch[0].length;
      continue;
    }

    // 9. Identifiers, Keywords, Rule Names, Modifiers
    const wordMatch = line.slice(i).match(/^[a-zA-Z_][a-zA-Z0-9_]*/);
    if (wordMatch) {
      const word = wordMatch[0];
      const lower = word.toLowerCase();

      // Check if preceded by 'rule ' keyword -> this is the rule name
      const prevNonWs = tokens.filter((t) => t.type !== 'plain').pop();
      if (prevNonWs && prevNonWs.type === 'keyword' && prevNonWs.text === 'rule') {
        tokens.push({ type: 'rule-name', text: word });
      } else if (YARA_KEYWORDS.has(lower)) {
        tokens.push({ type: 'keyword', text: word });
      } else if (YARA_MODIFIERS.has(lower)) {
        tokens.push({ type: 'modifier', text: word });
      } else {
        tokens.push({ type: 'plain', text: word });
      }
      i += word.length;
      continue;
    }

    // 10. Operators
    const opMatch = line.slice(i).match(/^(?:<=|>=|==|!=|<<|>>|=|<|>|\+|-|\*|\/|%|&|\||\^|~)/);
    if (opMatch) {
      tokens.push({ type: 'operator', text: opMatch[0] });
      i += opMatch[0].length;
      continue;
    }

    // 11. Punctuation
    if ('{}()[],:;'.includes(line[i])) {
      tokens.push({ type: 'punctuation', text: line[i] });
      i++;
      continue;
    }

    // 12. Fallback single char
    tokens.push({ type: 'plain', text: line[i] });
    i++;
  }

  return tokens;
}

/**
 * Returns strict brand-compliant styling classes for each YARA token.
 */
export function getYaraTokenClass(type: YaraToken['type']): string {
  switch (type) {
    case 'comment':
      return 'text-[#737373] italic';
    case 'section':
      return 'text-[#c30800] font-bold tracking-wider';
    case 'keyword':
      return 'text-[#c300bb] font-semibold';
    case 'modifier':
      return 'text-[#c36a00] font-semibold';
    case 'rule-name':
      return 'text-[#f0f0f0] font-bold tracking-wide';
    case 'variable':
      return 'text-[#bbc300] font-semibold';
    case 'regex':
      return 'text-[#c36a00] font-mono';
    case 'string':
      return 'text-[#bbc300]/90';
    case 'hex-string':
      return 'text-[#c36a00] font-mono';
    case 'number':
      return 'text-[#90e58c] font-mono';
    case 'operator':
      return 'text-[#c3005a] font-semibold';
    case 'punctuation':
      return 'text-[#8c8c8c]';
    case 'plain':
    default:
      return 'text-[#f0f0f0]';
  }
}

interface HighlightedYaraProps {
  code: string;
  showLineNumbers?: boolean;
}

/**
 * HighlightedYara component renders YARA rules with industrial dark-theme syntax highlighting
 * and optional line numbering.
 */
export const HighlightedYara: React.FC<HighlightedYaraProps> = ({
  code,
  showLineNumbers = true,
}) => {
  const lines = code.split('\n');

  return (
    <div className="font-mono text-xs leading-relaxed select-text">
      {lines.map((line, idx) => {
        const tokens = tokenizeYaraLine(line);
        const lineNum = idx + 1;

        return (
          <div key={lineNum} className="flex hover:bg-[#1a1a1a]/40 transition-colors">
            {showLineNumbers && (
              <span
                className="w-8 shrink-0 text-right pr-3 select-none text-[#737373] font-mono opacity-50"
                aria-hidden="true"
              >
                {lineNum}
              </span>
            )}
            <span className="flex-1 whitespace-pre overflow-x-visible">
              {tokens.length === 0 ? (
                '\u00A0'
              ) : (
                tokens.map((tok, tIdx) => (
                  <span key={tIdx} className={getYaraTokenClass(tok.type)}>
                    {tok.text}
                  </span>
                ))
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
};

export default HighlightedYara;
