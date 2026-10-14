// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect, useRef } from 'react';
import { RotateCcw } from 'lucide-react';
import { SkullLogo } from './SkullLogo';

interface HeaderProps {
  isExecuting: boolean;
  isReady: boolean;
  onReset: () => void;
  currentView?: 'compiler' | 'detections';
  onNavigate?: (view: 'compiler' | 'detections') => void;
}

const BRAND_NAME = '0xCONFUSED';
const SCRAMBLE_CHARS = '!@#$%^&*<>[]_01';

export const Header: React.FC<HeaderProps> = ({
  isExecuting,
  isReady,
  onReset,
  currentView = 'compiler',
  onNavigate,
}) => {
  const [scrambleText, setScrambleText] = useState<string>(BRAND_NAME);
  const lastHoverScrambleRef = useRef<number>(0);
  const scrambleIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const runScramble = () => {
    if (scrambleIntervalRef.current) {
      clearInterval(scrambleIntervalRef.current);
    }
    let iteration = 0;
    scrambleIntervalRef.current = setInterval(() => {
      setScrambleText(
        BRAND_NAME.split('')
          .map((_char, index) => {
            if (index < iteration) {
              return BRAND_NAME[index];
            }
            return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
          })
          .join('')
      );
      if (iteration >= BRAND_NAME.length) {
        if (scrambleIntervalRef.current) {
          clearInterval(scrambleIntervalRef.current);
          scrambleIntervalRef.current = null;
        }
        setScrambleText(BRAND_NAME);
      }
      iteration += 1 / 3;
    }, 30);
  };

  const handleMouseEnter = () => {
    const now = Date.now();
    if (now - lastHoverScrambleRef.current < 2000) {
      return;
    }
    lastHoverScrambleRef.current = now;
    runScramble();
  };

  useEffect(() => {
    runScramble();
    return () => {
      if (scrambleIntervalRef.current) {
        clearInterval(scrambleIntervalRef.current);
      }
    };
  }, []);

  return (
    <header id="drjekyll-header" className="topbar">
      <div className="topbar-inner">
        <div className="brand">
          <div className="brand-logo-slot">
            <div className="brand-logo-inner" aria-hidden="true">
              <SkullLogo
                size={64}
                className="w-16 h-16 object-contain opacity-100"
              />
            </div>
          </div>

          <div className="brand-text-wrap">
            <div className="brand-title-row">
              <h1
                className="brand-glitch-text font-glitch"
                id="brandGlitchText"
                data-text="0xCONFUSED"
                onMouseEnter={handleMouseEnter}
              >
                <span className="brand-title">{scrambleText}</span>
              </h1>
              <span className="brand-mod font-mono">./jekyll</span>
            </div>
            <p className="brand-tagline">
              Javascript Injection Platform
            </p>
          </div>
        </div>

        {/* Center Navigation Bar */}
        {onNavigate && (
          <nav className="hidden md:flex items-center gap-1.5 bg-[#141414] border border-[#383838] p-1 font-mono text-xs">
            <button
              type="button"
              onClick={() => onNavigate('compiler')}
              className={`px-3 py-1.5 transition-colors cursor-pointer flex items-center gap-1.5 ${
                currentView === 'compiler'
                  ? 'bg-[#262626] text-[#f0f0f0] font-bold border border-[#c30800]'
                  : 'text-[#8c8c8c] hover:text-[#f0f0f0] border border-transparent'
              }`}
            >
              <span>COMPILER</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('detections')}
              className={`px-3 py-1.5 transition-colors cursor-pointer flex items-center gap-1.5 ${
                currentView === 'detections'
                  ? 'bg-[#262626] text-[#f0f0f0] font-bold border border-[#c30800]'
                  : 'text-[#8c8c8c] hover:text-[#f0f0f0] border border-transparent'
              }`}
            >
              <span>DETECTION LOGIC</span>
            </button>
          </nav>
        )}

        <div className="topbar-actions">
          {/* Injection Engine Status */}
          <div className="flex flex-col items-start md:items-end">
            <span className="text-[10px] uppercase tracking-widest text-[#8c8c8c] font-mono font-semibold">
              Injection Engine
            </span>
            <span
              id="compiler-status-badge"
              className={`text-xs font-mono font-bold flex items-center gap-1.5 ${
                isExecuting
                  ? 'text-[#c30800]'
                  : isReady
                  ? 'text-[#bbc300]'
                  : 'text-[#8c8c8c]'
              }`}
            >
              <span
                className={`w-2 h-2 ${
                  isExecuting
                    ? 'bg-[#c30800] animate-pulse'
                    : isReady
                    ? 'bg-[#bbc300]'
                    : 'bg-[#383838]'
                }`}
              />
              {isExecuting ? 'RUNNING' : 'READY'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              id="reset-compiler-btn"
              onClick={onReset}
              title="Reset Uploaded Documents & Output"
              className="btn btn-secondary icon-btn text-[#8c8c8c] hover:text-[#f0f0f0] cursor-pointer"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
