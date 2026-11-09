// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useRef, useMemo, useEffect } from 'react';
import { Download, Copy, Check, Terminal, Code, Eye, RotateCw, Maximize2, Minimize2 } from 'lucide-react';
import { ExecutionResult } from '../types';
import { formatBytes, formatDuration } from '../utils/cryptoUtils';
import { diffLines } from '../utils/diffUtils';
import { InjectionSpinner } from './InjectionSpinner';
import { HighlightedCode } from './HighlightedCode';

export type ActivePreviewMode = 'none' | 'html' | 'js';

interface ExecutionConsoleCardProps {
  result: ExecutionResult | null;
  isExecuting: boolean;
  originalHtml?: string;
  inputHtml?: string;
  inputFileName?: string;
  inputJs?: string;
  inputJsFileName?: string;
  activePreviewMode?: ActivePreviewMode;
  onSelectPreviewMode?: (mode: ActivePreviewMode) => void;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
}

type OutputSubTab = 'preview' | 'source' | 'logs';

export const ExecutionConsoleCard: React.FC<ExecutionConsoleCardProps> = ({
  result,
  isExecuting,
  originalHtml = '',
  inputHtml = '',
  inputFileName = '',
  inputJs = '',
  inputJsFileName = '',
  activePreviewMode = 'none',
  onSelectPreviewMode,
  isExpanded = false,
  onToggleExpand,
}) => {
  const [activeTab, setActiveTab] = useState<OutputSubTab>('preview');
  const [copied, setCopied] = useState<boolean>(false);
  const [previewKey, setPreviewKey] = useState<number>(0);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);
  const codeScrollRef = useRef<HTMLDivElement>(null);
  const [scrollbarHeight, setScrollbarHeight] = useState<number>(0);

  const handleCodeScroll = (e: React.UIEvent<HTMLDivElement>) => {
    if (lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = e.currentTarget.scrollTop;
    }
    const h = e.currentTarget.offsetHeight - e.currentTarget.clientHeight;
    if (h !== scrollbarHeight) {
      setScrollbarHeight(h > 0 ? h : 0);
    }
  };

  const handleGutterWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    if (codeScrollRef.current) {
      codeScrollRef.current.scrollTop += e.deltaY;
    }
  };

  const isHtmlPreview = activePreviewMode === 'html' && Boolean(inputHtml);
  const isJsPreview = activePreviewMode === 'js' && Boolean(inputJs);
  const isInputPreview = isHtmlPreview || isJsPreview;
  const effectiveTab: OutputSubTab = isJsPreview ? 'source' : activeTab;

  const activeContent = isHtmlPreview
    ? inputHtml
    : isJsPreview
    ? inputJs
    : result?.outputFile?.content;

  const activeFileName = isHtmlPreview
    ? inputFileName || 'document.html'
    : isJsPreview
    ? inputJsFileName || 'payload.js'
    : result?.outputFile?.name || '{{filehash}}.html';

  const activeByteSize = activeContent
    ? new TextEncoder().encode(activeContent).length
    : 0;

  const getHeaderTitle = () => {
    if (activePreviewMode === 'html') {
      return 'INPUT 1: HTML DOCUMENT PREVIEW';
    }
    if (activePreviewMode === 'js') {
      return 'INPUT 2: JAVASCRIPT SOURCE PREVIEW';
    }
    return 'OUTPUT: HTML DOCUMENT';
  };

  const handleCopyArtifact = () => {
    if (activeContent) {
      navigator.clipboard.writeText(activeContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (isInputPreview && activeContent) {
      const mimeType = isHtmlPreview ? 'text/html' : 'text/javascript';
      const blob = new Blob([activeContent], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = activeFileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      return;
    }

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

  const currentLines = useMemo(() => {
    if (!activeContent) return [];
    return activeContent.split('\n');
  }, [activeContent]);

  const diffData = useMemo(() => {
    if (isInputPreview || !result?.outputFile?.content) return [];
    return diffLines(originalHtml, result.outputFile.content);
  }, [isInputPreview, originalHtml, result?.outputFile?.content]);

  const changedCount = useMemo(() => {
    return diffData.filter((d) => d.isChanged).length;
  }, [diffData]);

  useEffect(() => {
    const el = codeScrollRef.current;
    if (!el) return;

    const measure = () => {
      const h = el.offsetHeight - el.clientHeight;
      setScrollbarHeight(h > 0 ? h : 0);
    };

    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    window.addEventListener('resize', measure);
    const timer = setTimeout(measure, 250);

    return () => {
      clearTimeout(timer);
      ro.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [activeTab, isExpanded, currentLines, diffData, result]);

  const scrollbarClasses = isExpanded
    ? '[scrollbar-width:auto] [scrollbar-color:#383838_#141414]'
    : '[scrollbar-width:thin] [scrollbar-color:#383838_#141414] [&::-webkit-scrollbar]:w-[6px] [&::-webkit-scrollbar]:h-[6px] [&::-webkit-scrollbar-track]:bg-[#141414] [&::-webkit-scrollbar-thumb]:bg-[#383838] hover:[&::-webkit-scrollbar-thumb]:bg-[#c30800]';

  const previewSrcDoc = useMemo(() => {
    const scrollbarStyle = isExpanded
      ? `
<style data-preview-scrollbars>
* {
  scrollbar-color: #383838 #141414 !important;
  scrollbar-width: auto !important;
}
</style>
`
      : `
<style data-preview-scrollbars>
* {
  scrollbar-color: #383838 #141414 !important;
  scrollbar-width: thin !important;
}
::-webkit-scrollbar {
  width: 6px !important;
  height: 6px !important;
}
::-webkit-scrollbar-track {
  background: #141414 !important;
}
::-webkit-scrollbar-thumb {
  background: #383838 !important;
}
::-webkit-scrollbar-thumb:hover {
  background: #c30800 !important;
}
</style>
`;
    if (isHtmlPreview && inputHtml) {
      if (/<\/head\s*>/i.test(inputHtml)) {
        return inputHtml.replace(/<\/head\s*>/i, (m) => `${scrollbarStyle}${m}`);
      }
      return `${scrollbarStyle}${inputHtml}`;
    }

    const content = result?.outputFile?.content;
    if (!content) return '';
    if (/<\/head\s*>/i.test(content)) {
      return content.replace(/<\/head\s*>/i, (m) => `${scrollbarStyle}${m}`);
    }
    return `${scrollbarStyle}${content}`;
  }, [isExpanded, isHtmlPreview, inputHtml, result?.outputFile?.content]);

  const linesCount = result?.outputFile?.content ? result.outputFile.content.split('\n').length : 0;

  return (
    <div className="w-full bg-[#141414] border border-[#383838] flex flex-col h-full">
      {/* Top accent hairline */}
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Unified Minimalist Header Bar */}
      <div className="px-3 sm:px-4 py-2.5 bg-[#141414] border-b border-[#383838] flex flex-col gap-2 select-none">
        {/* Line 1: Title & File Info */}
        <div className="flex items-center justify-between gap-2.5 min-w-0 w-full">
          <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
            <span
              className={`w-2 h-2 shrink-0 ${
                isExecuting
                  ? 'bg-[#c30800] animate-pulse'
                  : isInputPreview
                  ? 'bg-[#c30800]'
                  : result
                  ? result.success
                    ? 'bg-[#c30800]'
                    : 'bg-[#c3005a]'
                  : 'bg-[#8c8c8c]'
              }`}
            />
            <h2 className="text-xs font-mono font-bold tracking-wider text-[#f0f0f0]">
              {getHeaderTitle()}
            </h2>

            {(isInputPreview || result?.outputFile) && (
              <span className="text-[11px] font-mono text-[#8c8c8c] bg-[#1a1a1a] px-2 py-0.5 border border-[#2e2e2e]">
                {activeFileName} &bull; {formatBytes(activeByteSize)}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {!result && !isInputPreview && (
              <span className="text-[10px] font-mono text-[#737373] uppercase tracking-wider">
                STANDBY
              </span>
            )}

            {onToggleExpand && (
              <button
                type="button"
                onClick={onToggleExpand}
                className={`px-2 py-0.5 text-[11px] font-mono border flex items-center gap-1 transition-colors cursor-pointer ${
                  isExpanded
                    ? 'border-[#c30800] bg-[#262626] text-[#f3f3f7] font-bold shadow-sm'
                    : 'border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0]'
                }`}
                title={isExpanded ? 'Restore standard layout' : 'Expand output window to full width'}
              >
                {isExpanded ? (
                  <>
                    <Minimize2 className="w-3 h-3 text-[#c30800]" />
                    <span className="hidden sm:inline">COLLAPSE</span>
                  </>
                ) : (
                  <>
                    <Maximize2 className="w-3 h-3 text-[#c30800]" />
                    <span className="hidden sm:inline">FULL WIDTH</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Line 2: Controls & Tabs */}
        {(result || isInputPreview) && (
          <div className="flex items-center justify-between gap-1.5 w-full flex-wrap pt-1 border-t border-[#2e2e2e]/60">
            {/* View Switcher */}
            {!isJsPreview ? (
              <div className="flex items-center border border-[#383838] bg-[#1a1a1a] p-0.5 mr-auto sm:mr-1">
                <button
                  type="button"
                  onClick={() => setActiveTab('preview')}
                  className={`px-2 py-0.5 text-[11px] font-mono tracking-wider flex items-center gap-1 transition-colors cursor-pointer ${
                    effectiveTab === 'preview'
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
                  className={`px-2 py-0.5 text-[11px] font-mono tracking-wider flex items-center gap-1 transition-colors cursor-pointer ${
                    effectiveTab === 'source'
                      ? 'bg-[#262626] text-[#f0f0f0] font-bold'
                      : 'text-[#8c8c8c] hover:text-[#f0f0f0]'
                  }`}
                >
                  <Code className="w-3 h-3 text-[#c30800]" />
                  <span>SOURCE</span>
                </button>

                {!isInputPreview && (
                  <button
                    type="button"
                    onClick={() => setActiveTab('logs')}
                    className={`px-2 py-0.5 text-[11px] font-mono tracking-wider flex items-center gap-1 transition-colors cursor-pointer ${
                      effectiveTab === 'logs'
                        ? 'bg-[#262626] text-[#f0f0f0] font-bold'
                        : 'text-[#8c8c8c] hover:text-[#f0f0f0]'
                    }`}
                  >
                    <Terminal className="w-3 h-3 text-[#c30800]" />
                    <span>LOGS</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="flex items-center border border-[#383838] bg-[#1a1a1a] px-2 py-0.5 mr-auto sm:mr-1 text-[11px] font-mono tracking-wider text-[#f0f0f0] font-bold gap-1 select-none">
                <Code className="w-3 h-3 text-[#c30800]" />
                <span>SOURCE</span>
              </div>
            )}

            {/* Right Action Buttons */}
            <div className="flex items-center gap-1.5 ml-auto">
              {/* Quick Actions */}
              {!isJsPreview && effectiveTab === 'preview' && (
                <button
                  type="button"
                  onClick={handleRefreshPreview}
                  title="Reload preview"
                  className="px-2 py-0.5 text-[11px] font-mono border border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <RotateCw className="w-3 h-3 text-[#c30800]" />
                  <span className="hidden md:inline">RELOAD</span>
                </button>
              )}

              {!isInputPreview && effectiveTab === 'source' && result?.outputFile?.content && (
                <span className="hidden sm:inline-flex items-center gap-1 text-[11px] font-mono border border-[#383838] bg-[#1a1a1a] px-2 py-0.5 text-[#8c8c8c]">
                  <span className="w-1.5 h-1.5 bg-[#c30800]" />
                  <span>DIFF: <strong className="text-[#f0f0f0]">{changedCount}</strong> INJECTED</span>
                </span>
              )}

              <button
                type="button"
                onClick={handleCopyArtifact}
                className="px-2 py-0.5 text-[11px] font-mono border border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center gap-1 transition-colors cursor-pointer"
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
                className="px-2.5 py-0.5 text-[11px] font-mono font-bold border border-[#c30800] bg-[#1a1a1a] hover:bg-[#262626] text-[#f0f0f0] flex items-center gap-1 transition-colors cursor-pointer"
              >
                <Download className="w-3 h-3 text-[#c30800]" />
                <span>DOWNLOAD</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Main Content Viewport — Unified dimensions across preview, source, and logs */}
      <div
        className={`relative w-full ${
          isExpanded
            ? 'h-[720px] min-h-[720px] max-h-[720px]'
            : 'h-[540px] min-h-[540px] max-h-[540px]'
        } bg-[#0d0d0d] flex flex-col overflow-hidden transition-all duration-200`}
      >
        {isExecuting ? (
          <div className="w-full h-full flex-1 flex flex-col items-center justify-center p-6 text-center">
            <InjectionSpinner className="w-12 h-12 text-[#c30800] mb-3.5" />
            <span className="font-mono text-xs text-[#f0f0f0] font-bold tracking-wider">
              COMPILING HTML ARTIFACT...
            </span>
          </div>
        ) : !result && !isInputPreview ? (
          /* Standby Minimalist Placeholder */
          <div className="w-full h-full flex-1 flex flex-col items-center justify-center p-6 text-center text-[#737373]">
            <Terminal className="w-8 h-8 mb-2 text-[#c30800]" />
            <span className="font-mono text-xs text-[#8c8c8c] font-semibold tracking-wider">
              NO OUTPUT ARTIFACT GENERATED
            </span>
            <span className="font-mono text-[11px] text-[#737373] mt-1">
              Upload an HTML document and JavaScript source to preview or compile.
            </span>
          </div>
        ) : effectiveTab === 'preview' ? (
          /* Live Render sandboxed iframe directly filling space with matching scrollbars */
          activeContent ? (
            <div className={`w-full h-full flex-1 overflow-auto bg-[#0d0d0d] ${scrollbarClasses}`}>
              <iframe
                key={previewKey}
                ref={iframeRef}
                srcDoc={previewSrcDoc}
                title={getHeaderTitle()}
                sandbox="allow-scripts allow-modals"
                className="w-full h-full border-none bg-white/5"
              />
            </div>
          ) : (
            <div className="p-6 text-center text-[#8c8c8c] font-mono text-xs">
              No content available to preview.
            </div>
          )
        ) : effectiveTab === 'source' ? (
          /* Raw Source Code View with Separated Line Numbers Gutter and Code Viewport */
          isInputPreview ? (
            <div className="relative w-full h-full flex-1 flex overflow-hidden bg-[#0d0d0d]">
              {/* Line Numbers Gutter — Permanently flush with left card boundary */}
              <div
                ref={lineNumbersRef}
                onWheel={handleGutterWheel}
                className="w-14 -ml-[1px] bg-[#141414] border-r border-[#2e2e2e] pt-3 text-right pr-2 select-none shrink-0 font-mono text-xs overflow-hidden shadow-[2px_0_4px_rgba(0,0,0,0.5)] z-10 flex flex-col justify-start"
              >
                <div>
                  {currentLines.map((_, idx) => (
                    <div
                      key={idx + 1}
                      className="leading-5 h-5 flex items-center justify-end text-[#737373] text-xs font-mono"
                    >
                      <span>{idx + 1}</span>
                    </div>
                  ))}
                </div>
                {/* 12px bottom padding matching py-3 */}
                <div className="h-3 shrink-0" aria-hidden="true" />
                {/* Dynamic spacer matching the horizontal scrollbar height */}
                {scrollbarHeight > 0 && (
                  <div
                    style={{ height: `${scrollbarHeight}px`, minHeight: `${scrollbarHeight}px` }}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                )}
              </div>

              {/* Source Lines — Scrollable horizontally and vertically without leaking across border */}
              <div
                ref={codeScrollRef}
                onScroll={handleCodeScroll}
                className={`flex-1 min-w-0 h-full overflow-auto py-3 bg-[#0d0d0d] ${scrollbarClasses}`}
              >
                <div className="inline-block min-w-full font-mono text-xs selection:bg-[#c30800] selection:text-[#f3f3f7]">
                  {currentLines.map((line, idx) => (
                    <div
                      key={idx + 1}
                      className="leading-5 h-5 px-3 whitespace-pre font-mono text-[#f0f0f0] border-l-2 border-transparent block w-full"
                    >
                      <HighlightedCode line={line} isAddedLine={false} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : result?.outputFile?.content ? (
            <div className="relative w-full h-full flex-1 flex overflow-hidden bg-[#0d0d0d]">
              {/* Line Numbers Gutter — Permanently flush with left card boundary */}
              <div
                ref={lineNumbersRef}
                onWheel={handleGutterWheel}
                className="w-14 -ml-[1px] bg-[#141414] border-r border-[#2e2e2e] pt-3 text-right pr-2 select-none shrink-0 font-mono text-xs overflow-hidden shadow-[2px_0_4px_rgba(0,0,0,0.5)] z-10 flex flex-col justify-start"
              >
                <div>
                  {diffData.map((item) => (
                    <div
                      key={item.lineNum}
                      className={`leading-5 h-5 flex items-center justify-end gap-1 text-xs font-mono ${
                        item.isChanged
                          ? 'text-[#c30800] font-bold'
                          : 'text-[#737373]'
                      }`}
                    >
                      {item.isChanged && (
                        <span className="text-xs text-[#c30800] leading-none font-bold">+</span>
                      )}
                      <span>{item.lineNum}</span>
                    </div>
                  ))}
                </div>
                {/* 12px bottom padding matching py-3 */}
                <div className="h-3 shrink-0" aria-hidden="true" />
                {/* Dynamic spacer matching the horizontal scrollbar height */}
                {scrollbarHeight > 0 && (
                  <div
                    style={{ height: `${scrollbarHeight}px`, minHeight: `${scrollbarHeight}px` }}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                )}
              </div>

              {/* Source Lines with Diff Highlighting — Scrollable horizontally and vertically without leaking across border */}
              <div
                ref={codeScrollRef}
                onScroll={handleCodeScroll}
                className={`flex-1 min-w-0 h-full overflow-auto py-3 bg-[#0d0d0d] ${scrollbarClasses}`}
              >
                <div className="inline-block min-w-full font-mono text-xs selection:bg-[#c30800] selection:text-[#f3f3f7]">
                  {diffData.map((item) => (
                    <div
                      key={item.lineNum}
                      className={`leading-5 h-5 px-3 whitespace-pre font-mono transition-colors block w-full ${
                        item.isChanged
                          ? 'bg-[#c30800]/20 border-l-2 border-[#c30800] text-[#f3f3f7]'
                          : 'text-[#f0f0f0] border-l-2 border-transparent'
                      }`}
                    >
                      <HighlightedCode
                        line={item.line}
                        isAddedLine={item.isChanged}
                        charSpans={item.charSpans}
                      />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-[#8c8c8c] font-mono text-xs">
              Output HTML was empty. Check LOGS tab.
            </div>
          )
        ) : (
          /* Stdout / Stderr Logs */
          result && (
            <div className={`w-full h-full flex-1 overflow-auto p-3 space-y-3 font-mono text-xs ${scrollbarClasses}`}>
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
          )
        )}
      </div>

      {/* Minimal Status Footer */}
      {(result || isInputPreview) && (
        <div className="px-3 py-1.5 bg-[#141414] border-t border-[#383838] flex items-center justify-between text-[11px] font-mono text-[#737373]">
          <div className="flex items-center gap-3">
            {isHtmlPreview ? (
              <>
                <span>STATUS: <span className="text-[#f0f0f0]">HTML PREVIEW</span></span>
                <span className="text-[#383838]">&bull;</span>
                <span>LINES: <span className="text-[#8c8c8c]">{currentLines.length}</span></span>
                <span className="text-[#383838]">&bull;</span>
                <span>SIZE: <span className="text-[#8c8c8c]">{formatBytes(activeByteSize)}</span></span>
              </>
            ) : isJsPreview ? (
              <>
                <span>STATUS: <span className="text-[#f0f0f0]">JAVASCRIPT PREVIEW</span></span>
                <span className="text-[#383838]">&bull;</span>
                <span>LINES: <span className="text-[#8c8c8c]">{currentLines.length}</span></span>
                <span className="text-[#383838]">&bull;</span>
                <span>SIZE: <span className="text-[#8c8c8c]">{formatBytes(activeByteSize)}</span></span>
              </>
            ) : result ? (
              <>
                <span>EXIT: <span className={result.success ? 'text-[#f0f0f0]' : 'text-[#c3005a]'}>{result.exitCode}</span></span>
                <span className="text-[#383838]">&bull;</span>
                <span>TIME: <span className="text-[#8c8c8c]">{formatDuration(result.durationMs)}</span></span>
                <span className="text-[#383838]">&bull;</span>
                <span>LINES: <span className="text-[#8c8c8c]">{linesCount}</span></span>
              </>
            ) : null}
          </div>
          {(isInputPreview ? activeFileName : result?.outputFile?.sha256) && (
            <span className="hidden md:inline text-[10px] text-[#737373]">
              {isInputPreview
                ? `FILE: ${activeFileName}`
                : `SHA-256: ${result?.outputFile?.sha256.slice(0, 12)}...`}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
