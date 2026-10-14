// SPDX-License-Identifier: AGPL-3.0-or-later

export interface EngineInput {
  html: string;
  js: string;
}

export interface EngineExecutionResult {
  html: string;
  stdout?: string;
  stderr?: string;
}

/**
 * Standardized JavaScript Injection Engine Interface
 * 
 * To add a new engine:
 * 1. Drop a new .ts or .js file into src/engines/
 * 2. Export an object satisfying this interface (either default export or named 'engine')
 * 3. Vite's import.meta.glob automatically registers it into the compiler matrix at build time.
 */
export interface StandardInjectionEngine {
  id: string;
  label: string;
  description: string;
  execute: (input: EngineInput) => Promise<EngineExecutionResult | string> | (EngineExecutionResult | string);
}
