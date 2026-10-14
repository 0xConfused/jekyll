// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ============================================================================
 * STANDARDIZED JAVASCRIPT INJECTION ENGINE TEMPLATE
 * ============================================================================
 * 
 * To add a new engine:
 * 1. Copy this file into `src/engines/<your_engine_name>.js` (or .ts).
 * 2. Configure `id`, `label`, `description`, and implement `execute({ html, js })`.
 * 3. Run `npm run build` or `npm run dev`. Vite's compile-time glob auto-registers
 *    the new engine into the UI dropdown and compiler matrix with zero config.
 * 4. The static dist (`npm run build`) runs entirely in-browser with zero server needed.
 *
 * @typedef {Object} EngineInput
 * @property {string} html - Raw HTML source code
 * @property {string} js - Raw JavaScript payload to inject
 *
 * @typedef {Object} EngineExecutionResult
 * @property {string} html - Transformed HTML output document
 * @property {string} [stdout] - Informational build and execution logs
 * @property {string} [stderr] - Warning or non-fatal diagnostic notes
 */

export const engine = {
  /** Unique engine identifier slug (e.g. 'custom_bundler') */
  id: 'custom_injector',

  /** Display label rendered in UI selector and detection specs */
  label: 'Custom Injector',

  /** Description rendered in UI and spec documentation */
  description: 'Custom JavaScript injection engine implementing DOM mount hooks.',

  /**
   * Transforms input HTML and JS into the compiled HTML artifact.
   * Can be synchronous or asynchronous (returning a Promise).
   *
   * @param {EngineInput} input
   * @returns {Promise<EngineExecutionResult | string> | EngineExecutionResult | string}
   */
  execute: ({ html, js }) => {
    const timestamp = new Date().toISOString();
    const scriptTag = `\n<script type="text/javascript">\n/* Injected at ${timestamp} */\n${js}\n</script>\n`;

    let compiledHtml = html;

    // Example injection strategy: append before </body> or EOF
    if (compiledHtml.includes('</body>')) {
      compiledHtml = compiledHtml.replace('</body>', `${scriptTag}</body>`);
    } else if (compiledHtml.includes('</html>')) {
      compiledHtml = compiledHtml.replace('</html>', `${scriptTag}</html>`);
    } else {
      compiledHtml = compiledHtml + scriptTag;
    }

    return {
      html: compiledHtml,
      stdout: `[CUSTOM_INJECTOR] Payload injected successfully at ${timestamp}.\n[OK] Size: ${compiledHtml.length} bytes.`,
    };
  },
};

export default engine;
