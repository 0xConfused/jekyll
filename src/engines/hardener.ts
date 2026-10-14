// SPDX-License-Identifier: AGPL-3.0-or-later

import { StandardInjectionEngine, EngineInput, EngineExecutionResult } from './types';

async function computeSha256Base64(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const binaryString = String.fromCharCode(...hashArray);
  return btoa(binaryString);
}

export const hardenerEngine: StandardInjectionEngine = {
  id: 'hardener',
  label: 'Security Hardened Assembler',
  description: 'Calculates cryptographic SHA-256 integrity hashes and injects strict Content Security Policy meta tags.',
  execute: async ({ html, js }: EngineInput): Promise<EngineExecutionResult> => {
    const timestamp = new Date().toISOString();
    const scriptHashBase64 = await computeSha256Base64(js);

    const cspMeta = `\n  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'sha256-${scriptHashBase64}' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none';">\n  <!-- Hardened by Security Assembler at ${timestamp} -->\n`;
    const wrappedJs = `\n<script type="text/javascript">\n${js}\n</script>\n`;

    let compiledHtml = html;

    // Inject CSP meta tag into <head> or at top of html
    if (compiledHtml.includes('<head>')) {
      compiledHtml = compiledHtml.replace('<head>', `<head>${cspMeta}`);
    } else if (compiledHtml.includes('<html>')) {
      compiledHtml = compiledHtml.replace('<html>', `<html>\n<head>${cspMeta}</head>`);
    } else {
      compiledHtml = `<head>${cspMeta}</head>\n${compiledHtml}`;
    }

    // Inline script
    if (compiledHtml.includes('</body>')) {
      compiledHtml = compiledHtml.replace('</body>', `${wrappedJs}</body>`);
    } else if (compiledHtml.includes('</html>')) {
      compiledHtml = compiledHtml.replace('</html>', `${wrappedJs}</html>`);
    } else {
      compiledHtml = compiledHtml + wrappedJs;
    }

    return {
      html: compiledHtml,
      stdout: `[HARDENER] Cryptographic digest: sha256-${scriptHashBase64}\n[HARDENER] Content-Security-Policy meta tag injected into document head.\n[OK] Hardened compilation complete.`,
    };
  },
};

export default hardenerEngine;
