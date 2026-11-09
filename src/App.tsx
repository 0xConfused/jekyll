// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect } from 'react';
import {
  EngineProfile,
  ExecutionResult,
  OutputFileArtifact,
} from './types';
import { Header } from './components/Header';
import { ScriptSelectorBar } from './components/ScriptSelectorBar';
import { HtmlUploadCard } from './components/HtmlUploadCard';
import { JsUploadCard } from './components/JsUploadCard';
import { ExecutionConsoleCard } from './components/ExecutionConsoleCard';
import { OwnershipWarningModal } from './components/OwnershipWarningModal';
import { Footer } from './components/Footer';
import { DetectionSpecsPage } from './components/DetectionSpecsPage';
import { getAllEngineProfiles, getEngine, DEFAULT_ENGINE_ID } from './engines';
import { computeSha256 } from './utils/cryptoUtils';

export default function App() {
  const [profiles] = useState<EngineProfile[]>(() => getAllEngineProfiles());
  const [selectedProfileId, setSelectedProfileId] = useState<string>(DEFAULT_ENGINE_ID);
  const [activeView, setActiveView] = useState<'compiler' | 'detections'>('compiler');

  // Upload inputs: 1 HTML and 1 JS (starts empty, user uploads their own files)
  const [htmlCode, setHtmlCode] = useState<string>('');
  const [htmlFileName, setHtmlFileName] = useState<string>('');
  const [jsCode, setJsCode] = useState<string>('');
  const [jsFileName, setJsFileName] = useState<string>('');

  // Output: 1 HTML file every time (strictly {{filehash}}.html)
  const [outputFileName, setOutputFileName] = useState<string>('{{filehash}}.html');

  // Execution state (ephemeral, no archive)
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [result, setResult] = useState<ExecutionResult | null>(null);
  const [activePreviewMode, setActivePreviewMode] = useState<'none' | 'html' | 'js'>('none');
  const [isExpandedOutput, setIsExpandedOutput] = useState<boolean>(false);

  // Ownership banner modal
  const [showOwnershipWarning, setShowOwnershipWarning] = useState<boolean>(() => {
    try {
      return !sessionStorage.getItem('0xconfused_runner_agreed');
    } catch {
      return true;
    }
  });

  const handleAgreeOwnership = () => {
    try {
      sessionStorage.setItem('0xconfused_runner_agreed', 'true');
    } catch {}
    setShowOwnershipWarning(false);
  };

  // Sync view state with URL hash and GitHub Pages SPA redirect
  useEffect(() => {
    try {
      const redirected = sessionStorage.getItem('redirect');
      if (redirected) {
        sessionStorage.removeItem('redirect');
        const url = new URL(redirected);
        const path = url.pathname.toLowerCase();
        if (path.includes('detection') || path.includes('spec') || url.hash.includes('detection')) {
          setActiveView('detections');
        }
      }
    } catch {}

    const handleHashChange = () => {
      const hash = window.location.hash.toLowerCase();
      if (hash.startsWith('#detection') || hash.startsWith('#spec')) {
        setActiveView('detections');
        const parts = hash.split('/');
        if (parts[1]) {
          const matched = profiles.find((p) => p.id === parts[1]);
          if (matched) {
            setSelectedProfileId(matched.id);
          }
        }
      } else if (hash === '#compiler' || hash === '' || hash === '#/') {
        setActiveView('compiler');
      }
    };

    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [profiles]);

  const handleNavigateView = (view: 'compiler' | 'detections') => {
    setActiveView(view);
    try {
      if (view === 'detections') {
        window.location.hash = `#detections/${selectedProfileId}`;
      } else {
        window.location.hash = '#compiler';
      }
    } catch {}
  };

  const handleSelectProfile = (id: string) => {
    setSelectedProfileId(id);
    const profile = profiles.find((p) => p.id === id);
    if (profile?.defaultOutputName) {
      setOutputFileName(profile.defaultOutputName);
    }
    if (activeView === 'detections') {
      try {
        window.location.hash = `#detections/${id}`;
      } catch {}
    }
  };

  const handleReset = () => {
    setHtmlCode('');
    setHtmlFileName('');
    setJsCode('');
    setJsFileName('');
    setOutputFileName('{{filehash}}.html');
    setResult(null);
    setActivePreviewMode('none');
  };

  const handleOpenDetections = (profileId: string) => {
    handleSelectProfile(profileId);
    setActiveView('detections');
    try {
      window.location.hash = `#detections/${profileId}`;
    } catch {}
  };

  const canExecute = Boolean(htmlCode.trim() && jsCode.trim());

  // Execute compiler matrix: 1 HTML + 1 JS -> 1 HTML output directly in browser
  const handleExecute = async () => {
    if (!canExecute || isExecuting) return;

    setIsExecuting(true);
    setResult(null);
    setActivePreviewMode('none');

    const startTime = performance.now();
    try {
      // Step 1: Compute input hashes
      const htmlSha = await computeSha256(htmlCode);
      const jsSha = await computeSha256(jsCode);

      // Step 2: Resolve standardized JavaScript engine and execute
      const engine = getEngine(selectedProfileId);
      const rawResult = await engine.execute({ html: htmlCode, js: jsCode });

      const compiledHtml = typeof rawResult === 'string' ? rawResult : rawResult.html;
      const stdout = typeof rawResult === 'string'
        ? `[OK] Compiled with ${engine.label}`
        : (rawResult.stdout || `[OK] Compiled with ${engine.label}`);
      const stderr = typeof rawResult === 'string' ? '' : (rawResult.stderr || '');

      // Step 3: Compute artifact SHA-256 and enforce {{filehash}}.html output naming
      const compiledSha256 = await computeSha256(compiledHtml);
      const finalFileName = `${compiledSha256}.html`;
      const durationMs = Math.max(1, Math.round(performance.now() - startTime));

      const outputFile: OutputFileArtifact = {
        name: finalFileName,
        size: new Blob([compiledHtml]).size,
        lines: compiledHtml.split('\n').length,
        sha256: compiledSha256,
        mimeType: 'text/html',
        content: compiledHtml,
        downloadUrl: '',
      };

      const execResult: ExecutionResult = {
        runId: 'exec-' + Date.now().toString(36),
        success: true,
        exitCode: 0,
        durationMs,
        timedOut: false,
        pipelineProfile: selectedProfileId,
        htmlSha256: htmlSha,
        jsSha256: jsSha,
        stdout,
        stderr,
        outputFile,
        timestamp: Date.now(),
      };

      setResult(execResult);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Compilation failed';
      const durationMs = Math.max(1, Math.round(performance.now() - startTime));
      const failResult: ExecutionResult = {
        runId: 'err-' + Date.now().toString(36),
        success: false,
        exitCode: 1,
        durationMs,
        timedOut: false,
        htmlSha256: '',
        jsSha256: '',
        stdout: '',
        stderr: `[EXECUTION FAULT] ${msg}`,
        outputFile: null,
        timestamp: Date.now(),
      };
      setResult(failResult);
    } finally {
      setIsExecuting(false);
    }
  };

  // Keyboard shortcut Ctrl+Enter or Cmd+Enter
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        handleExecute();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleExecute]);

  return (
    <div className="min-h-screen bg-[#0d0d0d] text-[#f0f0f0] flex flex-col font-sans selection:bg-[#c30800] selection:text-[#f3f3f7]">
      {/* Unified Top Navigation Header */}
      <Header
        isExecuting={isExecuting}
        isReady={canExecute}
        onReset={handleReset}
        currentView={activeView}
        onNavigate={handleNavigateView}
      />

      {/* Main Workspace Container */}
      <main
        className={`flex-1 w-full mx-auto p-3 sm:p-6 flex flex-col transition-all duration-200 ${
          isExpandedOutput ? 'max-w-none px-4 sm:px-8' : 'max-w-7xl'
        }`}
      >
        {activeView === 'detections' ? (
          <DetectionSpecsPage
            profiles={profiles}
            selectedProfileId={selectedProfileId}
            onSelectProfile={handleSelectProfile}
            onBackToCompiler={() => handleNavigateView('compiler')}
          />
        ) : (
          <>
            {/* Top Control Bar */}
            <ScriptSelectorBar
              profiles={profiles}
              selectedProfileId={selectedProfileId}
              onSelectProfile={handleSelectProfile}
              isExecuting={isExecuting}
              canExecute={canExecute}
              onExecute={handleExecute}
              onViewDetections={handleOpenDetections}
            />

            {/* Layout: Dedicated Upload Fields on Left, Output Console on Right (or full-width when expanded) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 items-start">
              {/* Left Column: Dedicated Upload Fields (Hidden when output is expanded) */}
              {!isExpandedOutput && (
                <div className="lg:col-span-5 flex flex-col gap-4">
                  {/* 1. HTML Upload Dropzone Card */}
                  <div className="w-full">
                    <HtmlUploadCard
                      value={htmlCode}
                      fileName={htmlFileName}
                      onFileLoaded={(content, name) => {
                        setHtmlCode(content);
                        setHtmlFileName(name);
                        setActivePreviewMode('html');
                      }}
                      onClear={() => {
                        setHtmlCode('');
                        setHtmlFileName('');
                        setActivePreviewMode((curr) => (curr === 'html' ? 'none' : curr));
                      }}
                      onPreview={() => {
                        setActivePreviewMode((curr) => (curr === 'html' ? 'none' : 'html'));
                      }}
                      isPreviewActive={activePreviewMode === 'html'}
                    />
                  </div>

                  {/* 2. JavaScript Upload Dropzone Card */}
                  <div className="w-full">
                    <JsUploadCard
                      value={jsCode}
                      fileName={jsFileName}
                      onFileLoaded={(content, name) => {
                        setJsCode(content);
                        setJsFileName(name);
                        setActivePreviewMode('js');
                      }}
                      onClear={() => {
                        setJsCode('');
                        setJsFileName('');
                        setActivePreviewMode((curr) => (curr === 'js' ? 'none' : curr));
                      }}
                      onPreview={() => {
                        setActivePreviewMode((curr) => (curr === 'js' ? 'none' : 'js'));
                      }}
                      isPreviewActive={activePreviewMode === 'js'}
                    />
                  </div>
                </div>
              )}

              {/* Output Column: Execution Output (1 HTML output with live preview & download) */}
              <div
                className={`${
                  isExpandedOutput ? 'lg:col-span-12 w-full' : 'lg:col-span-7'
                } flex flex-col transition-all duration-200`}
              >
                <ExecutionConsoleCard
                  result={result}
                  isExecuting={isExecuting}
                  originalHtml={htmlCode}
                  inputHtml={htmlCode}
                  inputFileName={htmlFileName}
                  inputJs={jsCode}
                  inputJsFileName={jsFileName}
                  activePreviewMode={activePreviewMode}
                  onSelectPreviewMode={setActivePreviewMode}
                  isExpanded={isExpandedOutput}
                  onToggleExpand={() => setIsExpandedOutput((prev) => !prev)}
                />
              </div>
            </div>
          </>
        )}
      </main>

      {/* Footer */}
      <Footer />

      {/* Ownership & Liability Advisory Modal */}
      <OwnershipWarningModal
        isOpen={showOwnershipWarning}
        onAgree={handleAgreeOwnership}
      />
    </div>
  );
}
