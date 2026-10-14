// SPDX-License-Identifier: AGPL-3.0-or-later

import { StandardInjectionEngine, EngineInput, EngineExecutionResult } from './types';

export const sandboxEngine: StandardInjectionEngine = {
  id: 'sandbox',
  label: 'Interactive Test Harness',
  description: 'Wraps HTML and JS inside an on-screen console telemetry interceptor and debugger harness.',
  execute: ({ html, js }: EngineInput): EngineExecutionResult => {
    const harnessJs = `
<script type="text/javascript">
(function() {
  window.__drjekyll_telemetry = window.__drjekyll_telemetry || [];
  var origLog = console.log;
  var origWarn = console.warn;
  var origError = console.error;

  function capture(type, args) {
    try {
      var entry = {
        type: type,
        timestamp: new Date().toISOString(),
        message: Array.prototype.slice.call(args).map(function(item) {
          if (typeof item === 'object') {
            try { return JSON.stringify(item); } catch(e) { return String(item); }
          }
          return String(item);
        }).join(' ')
      };
      window.__drjekyll_telemetry.push(entry);
    } catch(err) {}
  }

  console.log = function() { capture('log', arguments); origLog.apply(console, arguments); };
  console.warn = function() { capture('warn', arguments); origWarn.apply(console, arguments); };
  console.error = function() { capture('error', arguments); origError.apply(console, arguments); };

  window.addEventListener('error', function(e) {
    capture('unhandled_error', [e.message, 'at', e.filename + ':' + e.lineno]);
  });
})();
</script>
<script type="text/javascript">
/* --- PAYLOAD EXECUTION CONTEXT --- */
${js}
</script>
`;

    let compiledHtml = html;

    if (compiledHtml.includes('</body>')) {
      compiledHtml = compiledHtml.replace('</body>', `${harnessJs}\n</body>`);
    } else if (compiledHtml.includes('</html>')) {
      compiledHtml = compiledHtml.replace('</html>', `${harnessJs}\n</html>`);
    } else {
      compiledHtml = compiledHtml + harnessJs;
    }

    return {
      html: compiledHtml,
      stdout: `[SANDBOX] Runtime telemetry interceptor installed.\n[SANDBOX] Console stream hooked: window.__drjekyll_telemetry\n[OK] Interactive harness compiled.`,
    };
  },
};

export default sandboxEngine;
