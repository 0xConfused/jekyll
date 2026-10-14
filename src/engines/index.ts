// SPDX-License-Identifier: AGPL-3.0-or-later

import { StandardInjectionEngine } from './types';
import { EngineProfile } from '../types';

export * from './types';

/**
 * Dynamic Engine Auto-Discovery
 * 
 * Uses Vite's compile-time import.meta.glob to automatically import and register
 * every JavaScript or TypeScript engine file inside src/engines/*.{ts,js}.
 * 
 * Drop a new engine file (e.g. src/engines/custom_engine.ts) here and it is
 * automatically loaded, typed, and available in the UI without touching any configuration!
 */
interface EngineModule {
  default?: StandardInjectionEngine;
  engine?: StandardInjectionEngine;
  [key: string]: unknown;
}

const engineModules = import.meta.glob<EngineModule>(
  './*.{ts,js}',
  { eager: true }
);

export const REGISTERED_ENGINES: Record<string, StandardInjectionEngine> = {};

for (const [filePath, rawMod] of Object.entries(engineModules)) {
  const mod = rawMod as EngineModule;
  // Skip internal definition, barrel, example, and template files
  if (
    filePath.includes('types.') ||
    filePath.includes('index.') ||
    filePath.includes('.template.') ||
    filePath.includes('.example.') ||
    filePath.includes('.test.')
  ) {
    continue;
  }

  const candidate = (mod.default || mod.engine || Object.values(mod).find(
    (v): v is StandardInjectionEngine => Boolean(v && typeof v === 'object' && 'id' in v && 'execute' in v)
  )) as StandardInjectionEngine | undefined;

  if (candidate && candidate.id && typeof candidate.execute === 'function') {
    REGISTERED_ENGINES[candidate.id] = candidate;
  }
}

export const DEFAULT_ENGINE_ID = 'bundler';

export function getEngine(id: string): StandardInjectionEngine {
  return REGISTERED_ENGINES[id] || REGISTERED_ENGINES[DEFAULT_ENGINE_ID];
}

export function getAllEngineProfiles(): EngineProfile[] {
  return Object.values(REGISTERED_ENGINES).map((eng) => ({
    id: eng.id,
    label: eng.label,
    description: eng.description,
    defaultOutputName: '{{filehash}}.html',
  }));
}
