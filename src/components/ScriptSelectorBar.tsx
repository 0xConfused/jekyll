// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState } from 'react';
import { Play, Layers, ChevronDown } from 'lucide-react';
import { EngineProfile } from '../types';
import { InjectionSpinner } from './InjectionSpinner';

interface ScriptSelectorBarProps {
  profiles: EngineProfile[];
  selectedProfileId: string;
  onSelectProfile: (id: string) => void;
  isExecuting: boolean;
  canExecute: boolean;
  onExecute: () => void;
  onViewDetections?: (profileId: string) => void;
}

export const ScriptSelectorBar: React.FC<ScriptSelectorBarProps> = ({
  profiles,
  selectedProfileId,
  onSelectProfile,
  isExecuting,
  canExecute,
  onExecute,
  onViewDetections,
}) => {
  const [isDescriptionExpanded, setIsDescriptionExpanded] = useState<boolean>(false);
  const currentProfile = profiles.find((p) => p.id === selectedProfileId);

  return (
    <div className="w-full bg-[#141414] border border-[#383838] p-3 sm:p-4 mb-4">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 sm:gap-4 items-start">
        {/* Compilation Profile Selector */}
        <div className="lg:col-span-8 flex flex-col">
          <label className="text-xs font-mono font-semibold tracking-wider text-[#8c8c8c] flex items-center gap-1.5 h-5 mb-1.5">
            <Layers className="w-3.5 h-3.5 text-[#c30800]" />
            <span>PROCESSING COMPILATION PROFILE</span>
          </label>

          <select
            value={selectedProfileId}
            onChange={(e) => {
              onSelectProfile(e.target.value);
            }}
            className="w-full h-10 bg-[#1a1a1a] text-[#f0f0f0] border border-[#383838] px-3 text-xs sm:text-sm font-mono focus:border-[#c30800] focus:outline-none transition-colors"
          >
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.label}
              </option>
            ))}
          </select>

          {currentProfile && (
            <div className="mt-2 flex flex-col gap-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => setIsDescriptionExpanded((prev) => !prev)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setIsDescriptionExpanded((prev) => !prev);
                    }
                  }}
                  className="flex items-start gap-1.5 text-left flex-1 min-w-[200px] cursor-pointer group py-0.5 select-none focus:outline-none"
                  title={isDescriptionExpanded ? 'Click to collapse description' : 'Click to expand full description'}
                >
                  <ChevronDown
                    className={`w-3.5 h-3.5 text-[#c30800] shrink-0 mt-0.5 transition-transform duration-200 ${
                      isDescriptionExpanded ? 'rotate-180' : ''
                    }`}
                  />
                  <p
                    className={`text-[11px] font-sans transition-colors leading-relaxed ${
                      isDescriptionExpanded
                        ? 'text-[#f0f0f0]'
                        : 'line-clamp-1 text-[#8c8c8c] group-hover:text-[#f0f0f0]'
                    }`}
                  >
                    {currentProfile.description}
                  </p>
                </div>

                {onViewDetections && (
                  <button
                    type="button"
                    onClick={() => onViewDetections(selectedProfileId)}
                    className="text-[10px] font-mono text-[#c30800] hover:text-[#f60a00] underline decoration-[#c30800]/40 hover:decoration-[#f60a00] underline-offset-4 cursor-pointer shrink-0"
                  >
                    [ VIEW YARA &amp; REGEX DETECTIONS ]
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Primary Compile CTA */}
        <div className="lg:col-span-4 flex flex-col">
          <div className="h-5 mb-1.5 hidden lg:block" aria-hidden="true" />
          <button
            type="button"
            onClick={onExecute}
            disabled={isExecuting || !canExecute}
            className={`w-full h-10 px-4 font-mono text-xs sm:text-sm font-bold tracking-wider flex items-center justify-center gap-2 border transition-all ${
              isExecuting || !canExecute
                ? 'bg-[#262626] text-[#737373] border-[#383838] cursor-not-allowed'
                : 'bg-gradient-to-r from-[#c30800] to-[#770500] hover:from-[#f60a00] hover:to-[#c30800] text-[#f3f3f7] border-[#c30800] shadow-lg cursor-pointer'
            }`}
          >
            {isExecuting ? (
              <>
                <InjectionSpinner className="w-4 h-4 text-[#f3f3f7] shrink-0" />
                <span>COMPILING...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current shrink-0" />
                <span>COMPILE HTML</span>
              </>
            )}
          </button>
          <span className="text-[10px] font-mono text-[#737373] text-center mt-1 hidden sm:block">
            SHORTCUT: CTRL + ENTER
          </span>
        </div>
      </div>
    </div>
  );
};
