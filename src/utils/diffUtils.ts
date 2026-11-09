// SPDX-License-Identifier: AGPL-3.0-or-later

export interface CharDiffSpan {
  text: string;
  isAdded: boolean;
}

export interface DiffLine {
  line: string;
  lineNum: number;
  isChanged: boolean;
  charSpans?: CharDiffSpan[];
}

/**
 * Computes character-level differences between an original line and a modified line.
 * Flags characters that were inserted/added with isAdded: true.
 */
export function computeCharDiff(origLine: string, newLine: string): CharDiffSpan[] {
  if (!origLine) {
    return [{ text: newLine, isAdded: newLine.length > 0 }];
  }
  if (!newLine) {
    return [];
  }
  if (origLine === newLine) {
    return [{ text: newLine, isAdded: false }];
  }

  // Common prefix optimization
  let prefixLen = 0;
  const maxPrefix = Math.min(origLine.length, newLine.length);
  while (prefixLen < maxPrefix && origLine[prefixLen] === newLine[prefixLen]) {
    prefixLen++;
  }

  // Common suffix optimization
  let suffixLen = 0;
  const maxSuffix = Math.min(origLine.length - prefixLen, newLine.length - prefixLen);
  while (
    suffixLen < maxSuffix &&
    origLine[origLine.length - 1 - suffixLen] === newLine[newLine.length - 1 - suffixLen]
  ) {
    suffixLen++;
  }

  const origMid = origLine.slice(prefixLen, origLine.length - suffixLen);
  const newMid = newLine.slice(prefixLen, newLine.length - suffixLen);

  const spans: CharDiffSpan[] = [];
  if (prefixLen > 0) {
    spans.push({ text: newLine.slice(0, prefixLen), isAdded: false });
  }

  if (newMid.length > 0) {
    // If origMid is empty, everything in newMid was added
    if (origMid.length === 0) {
      spans.push({ text: newMid, isAdded: true });
    } else {
      // LCS for character level within the middle section (capped at 1000 chars for speed)
      if (origMid.length > 1000 || newMid.length > 1000) {
        spans.push({ text: newMid, isAdded: true });
      } else {
        const m = origMid.length;
        const n = newMid.length;
        const dp: Uint16Array[] = [];
        for (let i = 0; i <= m; i++) {
          dp[i] = new Uint16Array(n + 1);
        }

        for (let i = 0; i < m; i++) {
          for (let j = 0; j < n; j++) {
            if (origMid[i] === newMid[j]) {
              dp[i + 1][j + 1] = dp[i][j] + 1;
            } else {
              dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
            }
          }
        }

        // Backtrack
        const newMatched = new Uint8Array(n);
        let ci = m;
        let cj = n;
        while (ci > 0 && cj > 0) {
          if (origMid[ci - 1] === newMid[cj - 1]) {
            newMatched[cj - 1] = 1;
            ci--;
            cj--;
          } else if (dp[ci - 1][cj] >= dp[ci][cj - 1]) {
            ci--;
          } else {
            cj--;
          }
        }

        // Consolidate into contiguous spans
        let curText = '';
        let curAdded: boolean | null = null;
        for (let k = 0; k < n; k++) {
          const added = newMatched[k] === 0;
          if (curAdded === null) {
            curAdded = added;
            curText = newMid[k];
          } else if (curAdded === added) {
            curText += newMid[k];
          } else {
            spans.push({ text: curText, isAdded: curAdded });
            curAdded = added;
            curText = newMid[k];
          }
        }
        if (curText) {
          spans.push({ text: curText, isAdded: Boolean(curAdded) });
        }
      }
    }
  }

  if (suffixLen > 0) {
    spans.push({ text: newLine.slice(newLine.length - suffixLen), isAdded: false });
  }

  return spans;
}

/**
 * Strips isChanged from leading and trailing newlines (empty or whitespace-only lines)
 * within each contiguous diff hunk as well as overall document boundaries.
 */
function stripLeadingAndTrailingNewlines(diff: DiffLine[]): DiffLine[] {
  const n = diff.length;
  let i = 0;

  while (i < n) {
    if (!diff[i].isChanged) {
      i++;
      continue;
    }

    // Found start of a contiguous diff hunk
    const hunkStart = i;
    while (i < n && diff[i].isChanged) {
      i++;
    }
    const hunkEnd = i - 1; // inclusive

    // Un-flag leading empty/whitespace lines in this hunk
    let lead = hunkStart;
    while (lead <= hunkEnd && diff[lead].line.trim().length === 0) {
      diff[lead].isChanged = false;
      delete diff[lead].charSpans;
      lead++;
    }

    // Un-flag trailing empty/whitespace lines in this hunk
    let trail = hunkEnd;
    while (trail >= lead && diff[trail].line.trim().length === 0) {
      diff[trail].isChanged = false;
      delete diff[trail].charSpans;
      trail--;
    }
  }

  return diff;
}

/**
 * Computes line-by-line differences between original text and modified text.
 * Flags inserted or altered lines with isChanged: true.
 * For modified lines, computes character-level additions for bright highlighting.
 * Never highlights leading or trailing newlines within diffs.
 */
export function diffLines(origText?: string, newText?: string): DiffLine[] {
  const orig = origText || '';
  const modified = newText || '';

  const a = orig.split('\n');
  const b = modified.split('\n');
  const aLen = a.length;
  const bLen = b.length;

  if (!orig.trim()) {
    const raw = b.map((line, idx) => ({
      line,
      lineNum: idx + 1,
      isChanged: line.trim().length > 0,
      charSpans: line.trim().length > 0 ? [{ text: line, isAdded: true }] : undefined,
    }));
    return stripLeadingAndTrailingNewlines(raw);
  }

  // Fast-set fallback for very large documents (> 2500 lines) to prevent lag
  if (aLen > 2500 || bLen > 2500) {
    const aSet = new Set(a.map((l) => l.trim()));
    const raw = b.map((line, idx) => {
      const changed = line.trim().length > 0 && !aSet.has(line.trim());
      return {
        line,
        lineNum: idx + 1,
        isChanged: changed,
        charSpans: changed ? [{ text: line, isAdded: true }] : undefined,
      };
    });
    return stripLeadingAndTrailingNewlines(raw);
  }

  // Standard Longest Common Subsequence (LCS) matrix for lines
  const dp: Uint16Array[] = [];
  for (let i = 0; i <= aLen; i++) {
    dp[i] = new Uint16Array(bLen + 1);
  }

  for (let i = 0; i < aLen; i++) {
    for (let j = 0; j < bLen; j++) {
      if (a[i] === b[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  // Backtrack to map alignment between a and b
  const bMatched = new Uint8Array(bLen);
  const bOriginalMatch = new Int32Array(bLen).fill(-1);
  let i = aLen;
  let j = bLen;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      bMatched[j - 1] = 1;
      bOriginalMatch[j - 1] = i - 1;
      i--;
      j--;
    } else if (dp[i - 1][j] >= dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  // For unmatched lines in b, try to find the corresponding modified line in a nearby
  let lastAMatch = -1;
  const raw = b.map((line, idx) => {
    const isMatched = bMatched[idx] === 1;
    if (isMatched) {
      lastAMatch = bOriginalMatch[idx];
      return {
        line,
        lineNum: idx + 1,
        isChanged: false,
      };
    }

    // Line was added or changed
    // Check if next line in a can be paired for fine-grained char diff
    const candidateAIndex = lastAMatch + 1;
    let charSpans: CharDiffSpan[] | undefined;
    if (candidateAIndex >= 0 && candidateAIndex < aLen) {
      charSpans = computeCharDiff(a[candidateAIndex], line);
    } else {
      charSpans = [{ text: line, isAdded: true }];
    }

    return {
      line,
      lineNum: idx + 1,
      isChanged: true,
      charSpans,
    };
  });

  return stripLeadingAndTrailingNewlines(raw);
}
