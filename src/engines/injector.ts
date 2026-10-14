// SPDX-License-Identifier: AGPL-3.0-or-later

import { StandardInjectionEngine, EngineInput, EngineExecutionResult } from './types';

export const injectorEngine: StandardInjectionEngine = {
  id: 'injector',
  label: 'Dynamic Template & State Injector',
  description: 'Replaces template tags ({{APP_SCRIPT}}, <!-- MOUNT_SCRIPT -->) in the HTML with the JS payload.',
  execute: ({ html, js }: EngineInput): EngineExecutionResult => {
    const wrappedJs = `\n<script id="injected-template-state" type="text/javascript">\n${js}\n</script>\n`;

    let compiledHtml = html;
    let matchedTag = 'none';

    if (compiledHtml.includes('{{APP_SCRIPT}}')) {
      compiledHtml = compiledHtml.replace(/\{\{APP_SCRIPT\}\}/g, wrappedJs);
      matchedTag = '{{APP_SCRIPT}}';
    } else if (compiledHtml.includes('<!-- MOUNT_SCRIPT -->')) {
      compiledHtml = compiledHtml.replace(/<!--\s*MOUNT_SCRIPT\s*-->/g, wrappedJs);
      matchedTag = '<!-- MOUNT_SCRIPT -->';
    } else if (compiledHtml.includes('{{INJECTED_PAYLOAD}}')) {
      compiledHtml = compiledHtml.replace(/\{\{INJECTED_PAYLOAD\}\}/g, wrappedJs);
      matchedTag = '{{INJECTED_PAYLOAD}}';
    } else if (compiledHtml.includes('</body>')) {
      compiledHtml = compiledHtml.replace('</body>', `${wrappedJs}</body>`);
      matchedTag = 'fallback </body>';
    } else {
      compiledHtml = compiledHtml + wrappedJs;
      matchedTag = 'fallback EOF';
    }

    return {
      html: compiledHtml,
      stdout: `[INJECTOR] Hydrated via template placeholder: ${matchedTag}\n[INJECTOR] Script ID: injected-template-state\n[OK] Template injection complete.`,
    };
  },
};

export default injectorEngine;
