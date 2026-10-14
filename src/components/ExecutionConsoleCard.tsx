// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useRef } from 'react';
import { Download, Copy, Check, Terminal, Code, Eye, RotateCw } from 'lucide-react';
import { ExecutionResult } from '../types';
import { formatBytes, formatDuration } from '../utils/cryptoUtils';
import { InjectionSpinner } from './InjectionSpinner';

interface ExecutionConsoleCardProps {
  result: ExecutionResult | null;
  isExecuting: boolean;
}

type OutputSubTab = 'preview' | 'source' | 'logs';

export const ExecutionConsoleCard: React.FC<ExecutionConsoleCardProps> = ({
  result,
  isExecuting,
}) => {
  const [activeTab, setActiveTab] = useState<OutputSubTab>('preview');
  const [copied, setCopied] = useState<boolean>(false);
  const [previewKey, setPreviewKey] = useState<number>(0);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const handleCopyArtifact = () => {
    if (result?.outputFile?.content) {
      navigator.clipboard.writeText(result.outputFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (!result?.outputFile) return;

    if (result.outputFile.downloadUrl) {
      const link = document.createElement('a');
      link.href = result.outputFile.downloadUrl;
      link.download = result.outputFile.name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } else if (result.outputFile.content) {
      const blob = new Blob([result.outputFile.content], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = result.outputFile.name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }
  };

  const handleRefreshPreview = () => {
    setPreviewKey((k) => k + 1);
  };

  const linesCount = result?.outputFile?.content ? result.outputFile.content.split('\n').length : 0;

  return (
    <div className="w-full bg-[#141414] border border-[#383838] flex flex-col h-full">
      {/* Top accent hairline */}
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Unified Minimalist Header Bar */}
      <div className="px-3 sm:px-4 py-2 bg-[#141414] border-b border-[#383838] flex flex-wrap items-center justify-between gap-2 select-none">
        {/* Left: Title & File Badge */}
        <div className="flex items-center gap-2.5 min-w-0">
          <span
            className={`w-2 h-2 shrink-0 ${
              isExecuting
                ? 'bg-[#c30800] animate-pulse'
                : result
                ? result.success
                  ? 'bg-[#c30800]'
                  : 'bg-[#c3005a]'
                : 'bg-[#8c8c8c]'
            }`}
          />
          <h2 className="text-xs font-mono font-bold tracking-wider text-[#f0f0f0]">
            OUTPUT: HTML DOCUMENT
          </h2>

          {result?.outputFile && (
            <span className="hidden sm:inline-block text-[11px] font-mono text-[#8c8c8c] bg-[#1a1a1a] px-2 py-0.5 border border-[#2e2e2e]">
              {result.outputFile.name} &bull; {formatBytes(result.outputFile.size)}
            </span>
          )}
        </div>

        {/* Right: Controls & Tabs */}
        {result ? (
          <div className="flex items-center gap-1.5 flex-wrap">
            {/* View Switcher */}
            <div className="flex items-center border border-[#383838] bg-[#1a1a1a] p-0.5 mr-1">
              <button
                type="button"
                onClick={() => setActiveTab('preview')}
                className={`px-2 py-0.5 text-[11px] font-mono tracking-wider flex items-center gap-1 transition-colors ${
                  activeTab === 'preview'
                    ? 'bg-[#262626] text-[#f0f0f0] font-bold'
                    : 'text-[#8c8c8c] hover:text-[#f0f0f0]'
                }`}
              >
                <Eye className="w-3 h-3 text-[#c30800]" />
                <span>PREVIEW</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('source')}
                className={`px-2 py-0.5 text-[11px] font-mono tracking-wider flex items-center gap-1 transition-colors ${
                  activeTab === 'source'
                    ? 'bg-[#262626] text-[#f0f0f0] font-bold'
                    : 'text-[#8c8c8c] hover:text-[#f0f0f0]'
                }`}
              >
                <Code className="w-3 h-3 text-[#c30800]" />
                <span>SOURCE</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('logs')}
                className={`px-2 py-0.5 text-[11px] font-mono tracking-wider flex items-center gap-1 transition-colors ${
                  activeTab === 'logs'
                    ? 'bg-[#262626] text-[#f0f0f0] font-bold'
                    : 'text-[#8c8c8c] hover:text-[#f0f0f0]'
                }`}
              >
                <Terminal className="w-3 h-3 text-[#c30800]" />
                <span>LOGS</span>
              </button>
            </div>

            {/* Quick Actions */}
            {activeTab === 'preview' && (
              <button
                type="button"
                onClick={handleRefreshPreview}
                title="Reload preview"
                className="px-2 py-0.5 text-[11px] font-mono border border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center gap-1 transition-colors"
              >
                <RotateCw className="w-3 h-3 text-[#c30800]" />
                <span className="hidden md:inline">RELOAD</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleCopyArtifact}
              className="px-2 py-0.5 text-[11px] font-mono border border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center gap-1 transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3 h-3 text-[#c30800]" />
                  <span>COPIED</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3 text-[#c30800]" />
                  <span>COPY</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleDownload}
              className="px-2.5 py-0.5 text-[11px] font-mono font-bold border border-[#c30800] bg-[#1a1a1a] hover:bg-[#262626] text-[#f0f0f0] flex items-center gap-1 transition-colors"
            >
              <Download className="w-3 h-3 text-[#c30800]" />
              <span>DOWNLOAD</span>
            </button>
          </div>
        ) : (
          <span className="text-[10px] font-mono text-[#737373] uppercase tracking-wider">
            STANDBY
          </span>
        )}
      </div>

      {/* Main Content Viewport */}
      <div className="relative flex-1 min-h-[440px] bg-[#0d0d0d] overflow-auto flex flex-col">
        {isExecuting ? (
          <div className="flex-1 flex flex-col items-center justify-center p-6 text-center">
            <InjectionSpinner className="w-12 h-12 text-[#c30800] mb-3.5" />
            <span className="font-mono text-xs text-[#f0f0f0] font-bold tracking-wider">
              COMPILING HTML ARTIFACT...
            </span>
          </div>
        ) : !result ? (
          /* Standby Minimalist Placeholder */
          <div className="flex-1 flex flex-col items-center justify-center p-6 text-center text-[#737373]">
            <Terminal className="w-8 h-8 mb-2 text-[#c30800]" />
            <span className="font-mono text-xs text-[#8c8c8c] font-semibold tracking-wider">
              NO OUTPUT ARTIFACT GENERATED
            </span>
            <span className="font-mono text-[11px] text-[#737373] mt-1">
              Artifact will be compiled and saved as {'{{filehash}}.html'}.
            </span>
          </div>
        ) : activeTab === 'preview' ? (
          /* Live Render sandboxed iframe directly filling space */
          result.outputFile?.content ? (
            <iframe
              key={previewKey}
              ref={iframeRef}
              srcDoc={result.outputFile.content}
              title="Output HTML Render"
              sandbox="allow-scripts allow-modals"
              className="w-full flex-1 min-h-[440px] border-none bg-white/5"
            />
          ) : (
            <div className="p-6 text-center text-[#8c8c8c] font-mono text-xs">
              No HTML artifact content generated. Check LOGS tab.
            </div>
          )
        ) : activeTab === 'source' ? (
          /* Raw HTML Source Code View */
          result.outputFile?.content ? (
            <div className="flex min-h-full">
              <div className="w-12 bg-[#141414] border-r border-[#2e2e2e] py-3 text-right pr-2 text-[#737373] font-mono text-xs select-none shrink-0">
                {Array.from({ length: linesCount }).map((_, i) => (
                  <div key={i} className="leading-5 h-5">
                    {i + 1}
                  </div>
                ))}
              </div>
              <pre className="p-3 text-xs font-mono text-[#f0f0f0] leading-5 whitespace-pre overflow-x-auto selection:bg-[#c30800] selection:text-[#f3f3f7] flex-1">
                <code>{result.outputFile.content}</code>
              </pre>
            </div>
          ) : (
            <div className="p-6 text-center text-[#8c8c8c] font-mono text-xs">
              Output HTML was empty. Check LOGS tab.
            </div>
          )
        ) : (
          /* Stdout / Stderr Logs */
          <div className="p-3 space-y-3 font-mono text-xs">
            {result.stdout && (
              <div>
                <div className="text-[10px] uppercase text-[#c30800] font-bold mb-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-[#c30800]" />
                  <span>PROCESS STDOUT:</span>
                </div>
                <pre className="p-3 bg-[#141414] border border-[#383838] text-[#f0f0f0] whitespace-pre-wrap selection:bg-[#c30800]">
                  {result.stdout}
                </pre>
              </div>
            )}

            {result.stderr && (
              <div>
                <div className="text-[10px] uppercase text-[#c30800] font-bold mb-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-[#c30800]" />
                  <span>PROCESS STDERR:</span>
                </div>
                <pre className="p-3 bg-[#141414] border border-[#c3005a]/40 text-[#c3005a] whitespace-pre-wrap selection:bg-[#c30800]">
                  {result.stderr}
                </pre>
              </div>
            )}

            {!result.stdout && !result.stderr && (
              <div className="text-center text-[#737373] py-8">
                No process logs emitted.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Minimal Status Footer */}
      {result && (
        <div className="px-3 py-1.5 bg-[#141414] border-t border-[#383838] flex items-center justify-between text-[11px] font-mono text-[#737373]">
          <div className="flex items-center gap-3">
            <span>EXIT: <span className={result.success ? 'text-[#f0f0f0]' : 'text-[#c3005a]'}>{result.exitCode}</span></span>
            <span className="text-[#383838]">&bull;</span>
            <span>TIME: <span className="text-[#8c8c8c]">{formatDuration(result.durationMs)}</span></span>
            <span className="text-[#383838]">&bull;</span>
            <span>LINES: <span className="text-[#8c8c8c]">{linesCount}</span></span>
          </div>
          {result.outputFile?.sha256 && (
            <span className="hidden md:inline text-[10px] text-[#737373]">
              SHA-256: {result.outputFile.sha256.slice(0, 12)}...
            </span>
          )}
        </div>
      )}
    </div>
  );
};
