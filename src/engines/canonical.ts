// SPDX-License-Identifier: AGPL-3.0-or-later

import { StandardInjectionEngine, EngineInput, EngineExecutionResult } from './types';

export const canonicalEngine: StandardInjectionEngine = {
  id: 'canonical',
  label: 'Canonical Core Runner',
  description: 'Canonical baseline compiler integrating HTML and JS.',
  execute: ({ html, js }: EngineInput): EngineExecutionResult => {
    const canonicalStamp = `\n<!-- CANONICAL_BUNDLE_V1 data-compiler="jekyll" -->\n<script type="text/javascript">\n${js}\n</script>\n`;

    let compiledHtml = html;

    if (compiledHtml.includes('</body>')) {
      compiledHtml = compiledHtml.replace('</body>', `${canonicalStamp}</body>`);
    } else if (compiledHtml.includes('</html>')) {
      compiledHtml = compiledHtml.replace('</html>', `${canonicalStamp}</html>`);
    } else {
      compiledHtml = compiledHtml + canonicalStamp;
    }

    return {
      html: compiledHtml,
      stdout: `[CANONICAL] Canonical stamp CANONICAL_BUNDLE_V1 applied.\n[CANONICAL] Stream appended at body termination.\n[OK] Canonical bundle ready.`,
    };
  },
};

export default canonicalEngine;
