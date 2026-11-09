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

const discovered: StandardInjectionEngine[] = [];

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
    discovered.push(candidate);
  }
}

// Sort discovered engines strictly in alphabetical order by their display label
discovered.sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: 'base' }));

export const REGISTERED_ENGINES: Record<string, StandardInjectionEngine> = {};
for (const eng of discovered) {
  REGISTERED_ENGINES[eng.id] = eng;
}

// Legacy engine ID mapping for backward compatibility
const LEGACY_ENGINE_MAP: Record<string, string> = {
  'element-hook': 'dom-method-hook',
  'code-camo': 'property-access-obfuscator',
  'codecamo': 'property-access-obfuscator',
  'hidden-img-xor': 'image-onerror-xor',
  'html-char-packer': 'dom-charset-packer',
  'lsb-stego': 'canvas-lsb-steganography',
  'url-matrix': 'url-coordinate-matrix',
  'zip-appender': 'image-zip-polyglot',
};

// First engine in alphabetical order is the default
export const DEFAULT_ENGINE_ID = discovered[0]?.id || 'dom-method-hook';

export function getEngine(id: string): StandardInjectionEngine {
  const resolvedId = LEGACY_ENGINE_MAP[id] || id;
  return REGISTERED_ENGINES[resolvedId] || REGISTERED_ENGINES[DEFAULT_ENGINE_ID] || Object.values(REGISTERED_ENGINES)[0];
}

export function getAllEngineProfiles(): EngineProfile[] {
  return discovered.map((eng) => ({
    id: eng.id,
    label: eng.label,
    description: eng.description,
    defaultOutputName: '{{filehash}}.html',
  }));
}
