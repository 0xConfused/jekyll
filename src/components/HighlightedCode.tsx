// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { CharDiffSpan } from '../utils/diffUtils';

/**
 * Token types for syntax highlighting in HTML / JavaScript code viewer.
 */
type TokenType =
  | 'tag'
  | 'attr-name'
  | 'comment'
  | 'string'
  | 'keyword'
  | 'number'
  | 'operator'
  | 'punctuation'
  | 'identifier'
  | 'text';

interface SyntaxToken {
  type: TokenType;
  text: string;
}

const JS_KEYWORDS = new Set([
  'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while',
  'do', 'switch', 'case', 'default', 'break', 'continue', 'new', 'try',
  'catch', 'finally', 'throw', 'typeof', 'instanceof', 'void', 'delete',
  'in', 'of', 'this', 'class', 'extends', 'super', 'import', 'export',
  'from', 'as', 'async', 'await', 'yield', 'true', 'false', 'null', 'undefined'
]);

/**
 * Tokenizes a string of HTML/JS for syntax highlighting.
 */
function tokenizeString(str: string): SyntaxToken[] {
  const tokens: SyntaxToken[] = [];
  let i = 0;
  const len = str.length;

  while (i < len) {
    // Comments
    if (str.startsWith('<!--', i)) {
      const end = str.indexOf('-->', i);
      const comment = end === -1 ? str.slice(i) : str.slice(i, end + 3);
      tokens.push({ type: 'comment', text: comment });
      i += comment.length;
      continue;
    }
    if (str.startsWith('//', i)) {
      tokens.push({ type: 'comment', text: str.slice(i) });
      break;
    }
    if (str.startsWith('/*', i)) {
      const end = str.indexOf('*/', i);
      const comment = end === -1 ? str.slice(i) : str.slice(i, end + 2);
      tokens.push({ type: 'comment', text: comment });
      i += comment.length;
      continue;
    }

    // HTML closing or opening tags: </tag or <tag or <!
    if (str[i] === '<') {
      const tagMatch = str.slice(i).match(/^<\/?([a-zA-Z0-9:-]+)/);
      if (tagMatch) {
        tokens.push({ type: 'tag', text: tagMatch[0] });
        i += tagMatch[0].length;
        continue;
      }
      tokens.push({ type: 'punctuation', text: '<' });
      i++;
      continue;
    }

    // Strings: single, double, backtick
    if (str[i] === '"' || str[i] === "'" || str[i] === '`') {
      const quote = str[i];
      let j = i + 1;
      while (j < len && str[j] !== quote) {
        if (str[j] === '\\') j++; // skip escaped
        j++;
      }
      if (j < len) j++; // include closing quote
      const s = str.slice(i, j);
      tokens.push({ type: 'string', text: s });
      i = j;
      continue;
    }

    // Numbers (hex, float, decimal)
    const numMatch = str.slice(i).match(/^(?:0x[a-fA-F0-9]+|\d+(?:\.\d+)?)/);
    if (numMatch && (i === 0 || /[^a-zA-Z0-9_$]/.test(str[i - 1]))) {
      tokens.push({ type: 'number', text: numMatch[0] });
      i += numMatch[0].length;
      continue;
    }

    // Identifiers & Keywords / HTML Attribute names
    const idMatch = str.slice(i).match(/^[a-zA-Z_$][a-zA-Z0-9_$-]*/);
    if (idMatch) {
      const id = idMatch[0];
      if (JS_KEYWORDS.has(id)) {
        tokens.push({ type: 'keyword', text: id });
      } else if (i + id.length < len && str[i + id.length] === '=') {
        tokens.push({ type: 'attr-name', text: id });
      } else {
        tokens.push({ type: 'identifier', text: id });
      }
      i += id.length;
      continue;
    }

    // Operators and punctuation
    const char = str[i];
    if ('=+-*/%&|^!~?:<>'.includes(char)) {
      tokens.push({ type: 'operator', text: char });
      i++;
      continue;
    }

    if ('{}()[].,;'.includes(char)) {
      tokens.push({ type: 'punctuation', text: char });
      i++;
      continue;
    }

    // Whitespace or plain text
    tokens.push({ type: 'text', text: char });
    i++;
  }

  return tokens;
}

/**
 * Returns text color class based on token type adhering to 0xCONFUSED dark palette.
 */
function getTokenTextColor(type: TokenType): string {
  switch (type) {
    case 'tag':
      return 'text-[#ff5555] font-semibold'; // Crisp tag red/coral
    case 'keyword':
      return 'text-[#ff79c6] font-semibold'; // Secondary magenta
    case 'attr-name':
      return 'text-[#ffb86c]'; // Warm amber
    case 'string':
      return 'text-[#f1fa8c]'; // Clean yellow
    case 'number':
      return 'text-[#50fa7b]'; // Terminal green
    case 'comment':
      return 'text-[#737373] italic';
    case 'operator':
      return 'text-[#ff6b6b]';
    case 'punctuation':
      return 'text-[#e0e0e0]';
    case 'identifier':
      return 'text-[#f0f0f0]';
    case 'text':
    default:
      return 'text-[#f0f0f0]';
  }
}

interface HighlightedCodeProps {
  line: string;
  isAddedLine?: boolean;
  charSpans?: CharDiffSpan[];
}

export const HighlightedCode: React.FC<HighlightedCodeProps> = React.memo(
  ({ line, isAddedLine = false, charSpans }) => {
    if (!line) {
      return <span> </span>;
    }

    // If character diff spans are available, highlight added characters with brighter background
    if (charSpans && charSpans.length > 0) {
      return (
        <code>
          {charSpans.map((span, sIdx) => {
            const tokens = tokenizeString(span.text);
            const spanBgClass = span.isAdded
              ? 'bg-[#c30800]/55 text-white shadow-[0_0_8px_rgba(195,8,0,0.4)] rounded-none px-0.5'
              : '';

            return (
              <span key={sIdx} className={spanBgClass}>
                {tokens.map((token, tIdx) => (
                  <span key={tIdx} className={getTokenTextColor(token.type)}>
                    {token.text}
                  </span>
                ))}
              </span>
            );
          })}
        </code>
      );
    }

    // Default line-level tokenize (e.g. for whole lines or preview)
    const tokens = tokenizeString(line);

    return (
      <code>
        {tokens.map((token, index) => {
          return (
            <span key={index} className={getTokenTextColor(token.type)}>
              {token.text}
            </span>
          );
        })}
      </code>
    );
  }
);
