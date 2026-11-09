<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Standardized JavaScript Injection Engines

All compilation and injection engines in this platform are standardized JavaScript/TypeScript modules executed entirely in-browser. No server or backend runtime is required.

## Architecture

- **Engine Discovery**: At build time and in local dev, Vite automatically scans `src/engines/*.{js,ts}` using `import.meta.glob`.
- **Zero Config**: Any file placed in `src/engines/` conforming to the standard specification is instantly registered into:
  1. The compiler profile dropdown (`ScriptSelectorBar`).
  2. The compiler execution pipeline (`App.tsx`).
  3. The detection rules and YARA/regex specification generator (`DetectionSpecsPage`).
- **Static Compilation**: Building the npm package (`npm run build`) bundles all engines and generates a 100% static distribution (`dist/`) that can be hosted on GitHub Pages, S3, Netlify, Cloudflare Pages, or opened directly with no server.

## Engine Interface Specification

Every engine module must export an object satisfying the following contract (either as `export default` or `export const engine`):

```javascript
// SPDX-License-Identifier: AGPL-3.0-or-later

export const engine = {
  // Unique machine-readable identifier
  id: 'my_custom_engine',

  // Human-readable title for UI controls
  label: 'My Custom Engine',

  // Detailed operational summary
  description: 'This engine appends the JavaScript payload before the closing body tag.',

  // Execution transformer
  execute: ({ html, js }) => {
    // Perform transformation
    const transformedHtml = html.replace('</body>', `<script>${js}</script></body>`);

    return {
      html: transformedHtml,
      stdout: '[MY_ENGINE] Compilation completed successfully.',
      stderr: '', // Optional non-fatal warnings
    };
  },
};

export default engine;
```

### Parameters (`EngineInput`)

| Field | Type | Description |
|---|---|---|
| `html` | `string` | Raw HTML source document from upload field |
| `js` | `string` | Raw JavaScript source payload from upload field |

### Return Value (`EngineExecutionResult`)

The `execute` function may return synchronously or return a `Promise`. The returned value can be either:

1. An object `{ html: string, stdout?: string, stderr?: string }`
2. A raw string containing the compiled HTML output document.

## Adding a New Engine

1. Copy `src/engines/engine.template.js` to `src/engines/<your_engine_name>.js`.
2. Implement your custom AST parsing, regex replacement, or script concatenation logic inside `execute`.
3. Run `npm run build`. The generated `dist/` contains the fully updated, self-contained static application.
