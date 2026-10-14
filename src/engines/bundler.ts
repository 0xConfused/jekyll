// SPDX-License-Identifier: AGPL-3.0-or-later

import { StandardInjectionEngine, EngineInput, EngineExecutionResult } from './types';

export const bundlerEngine: StandardInjectionEngine = {
  id: 'bundler',
  label: 'Standard Standalone Bundler',
  description: 'Inlines JavaScript directly into the HTML document producing a standalone single HTML artifact.',
  execute: ({ html, js }: EngineInput): EngineExecutionResult => {
    const timestamp = new Date().toISOString();
    const banner = `/* Bundled at ${timestamp} */\n`;
    const wrappedJs = `\n<script type="text/javascript">\n${banner}${js}\n</script>\n`;

    let compiledHtml = html;

    if (compiledHtml.includes('<!-- INJECT_JS -->')) {
      compiledHtml = compiledHtml.replace('<!-- INJECT_JS -->', wrappedJs);
    } else if (compiledHtml.includes('<!-- SCRIPT -->')) {
      compiledHtml = compiledHtml.replace('<!-- SCRIPT -->', wrappedJs);
    } else if (/<script\s+[^>]*src=['"][^'"]*['"][^>]*>\s*<\/script>/i.test(compiledHtml)) {
      compiledHtml = compiledHtml.replace(/<script\s+[^>]*src=['"][^'"]*['"][^>]*>\s*<\/script>/i, wrappedJs);
    } else if (compiledHtml.includes('</body>')) {
      compiledHtml = compiledHtml.replace('</body>', `${wrappedJs}</body>`);
    } else if (compiledHtml.includes('</html>')) {
      compiledHtml = compiledHtml.replace('</html>', `${wrappedJs}</html>`);
    } else {
      compiledHtml = compiledHtml + wrappedJs;
    }

    return {
      html: compiledHtml,
      stdout: `[BUNDLER] JavaScript payload inlined at ${timestamp}.\n[BUNDLER] Size: ${compiledHtml.length} bytes.\n[OK] Compilation successful.`,
    };
  },
};

export default bundlerEngine;
