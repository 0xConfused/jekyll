<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ./jekyll — JavaScript Injection Platform

A zero-server, high-performance static compiler platform for combining HTML documents and JavaScript payloads into standalone artifacts. All processing occurs entirely in-browser using standardized client-side JavaScript engines.

---

## Architecture Overview

The compiler workflow processes two uploaded inputs—**one HTML file** and **one JavaScript file**—and executes a selected standardized JavaScript engine to generate **one unified HTML output artifact** named `{{filehash}}.html` (where hash is the SHA-256 digest of the compiled document).

### Core Highlights
- **Zero Server Dependency**: The compiled npm application produces a completely static distribution (`dist/`) requiring no backend or container runtime.
- **Dynamic Engine Auto-Discovery**: Dropping any `.js` or `.ts` file into `src/engines/` automatically registers it into the compiler matrix at build time via Vite's `import.meta.glob`.
- **In-Browser Execution**: All AST transformations, script injection, CSP calculation, and SHA-256 cryptographic digests run via Web Crypto and native ECMAScript engines.
- **Dynamic Detection Rules**: Every profile automatically receives corresponding YARA detection rules, ECMAScript regular expressions, and SIEM queries.

---

## Adding a New JavaScript Engine

Engines are fully standardized. To add a new engine:

1. Create a new file in `src/engines/` (e.g. `src/engines/custom_injector.js` or `src/engines/custom_injector.ts`).
2. Export an object satisfying the standard `StandardInjectionEngine` contract:

```javascript
// SPDX-License-Identifier: AGPL-3.0-or-later

export const engine = {
  id: 'my_custom_engine',
  label: 'My Custom Engine',
  description: 'Custom DOM injection engine.',
  execute: ({ html, js }) => {
    // Transform inputs
    const compiled = html.replace('</body>', `<script>${js}</script></body>`);
    return {
      html: compiled,
      stdout: '[MY_ENGINE] Successfully compiled artifact.',
    };
  },
};

export default engine;
```

3. Run `npm run build` or `npm run dev`. Vite automatically registers the new engine into the UI dropdown and execution pipeline with zero additional configuration.

---

## Static Build & Deployment

To compile the self-contained static distribution:

```bash
npm run build
```

The resulting `dist/` directory contains:
- `index.html`: Standalone application entrypoint.
- `assets/`: Optimized JavaScript bundles and Tailwind CSS styles.

The contents of `dist/` can be served directly from any static web server, object store (S3, GCS), or CDN without Node.js or Python backend processes.
