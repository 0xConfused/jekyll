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

const INITIAL_SAMPLE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Host Container</title>
  <style>
    body {
      background: #0d0d0d;
      color: #f0f0f0;
      font-family: monospace;
      margin: 0;
      padding: 30px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      box-sizing: border-box;
    }
    .box {
      background: #141414;
      border: 1px solid #383838;
      border-top: 3px solid #c30800;
      padding: 24px;
      max-width: 540px;
      width: 100%;
    }
    h1 { font-size: 16px; margin: 0 0 10px 0; color: #f0f0f0; }
    #target-area {
      margin-top: 16px;
      padding: 12px;
      background: #0d0d0d;
      border: 1px solid #2e2e2e;
      color: #bbc300;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>HOST APPARATUS CONTAINER</h1>
    <div id="target-area">Awaiting script integration...</div>
  </div>
</body>
</html>`;

const INITIAL_SAMPLE_JS = `// Interactive DOM Logic
document.addEventListener("DOMContentLoaded", function() {
  var target = document.getElementById("target-area") || document.body;
  target.innerHTML = "";

  var status = document.createElement("div");
  status.style.color = "#bbc300";
  status.style.fontWeight = "bold";
  status.textContent = "Status: Script Subsystem Active.";

  var btn = document.createElement("button");
  btn.textContent = "DISPATCH PULSE";
  btn.style.marginTop = "10px";
  btn.style.padding = "6px 14px";
  btn.style.background = "#c30800";
  btn.style.color = "#f3f3f7";
  btn.style.border = "none";
  btn.style.cursor = "pointer";
  btn.style.fontFamily = "monospace";

  var count = 0;
  btn.onclick = function() {
    count++;
    status.textContent = "Telemetry Pulses Recorded: " + count;
    console.log("[TELEMETRY]", count, new Date().toISOString());
  };

  target.appendChild(status);
  target.appendChild(btn);
});`;

export default function App() {
  const [profiles] = useState<EngineProfile[]>(() => getAllEngineProfiles());
  const [selectedProfileId, setSelectedProfileId] = useState<string>(DEFAULT_ENGINE_ID);
  const [activeView, setActiveView] = useState<'compiler' | 'detections'>('compiler');
  const [activeDetectionProfileId, setActiveDetectionProfileId] = useState<string>(DEFAULT_ENGINE_ID);

  // Upload inputs: 1 HTML and 1 JS
  const [htmlCode, setHtmlCode] = useState<string>(INITIAL_SAMPLE_HTML);
  const [htmlFileName, setHtmlFileName] = useState<string>('index.html');
  const [jsCode, setJsCode] = useState<string>(INITIAL_SAMPLE_JS);
  const [jsFileName, setJsFileName] = useState<string>('script.js');

  // Output: 1 HTML file every time (strictly {{filehash}}.html)
  const [outputFileName, setOutputFileName] = useState<string>('{{filehash}}.html');

  // Execution state (ephemeral, no archive)
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [result, setResult] = useState<ExecutionResult | null>(null);

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

  const handleSelectProfile = (id: string) => {
    setSelectedProfileId(id);
    const profile = profiles.find((p) => p.id === id);
    if (profile?.defaultOutputName) {
      setOutputFileName(profile.defaultOutputName);
    }
  };

  const handleReset = () => {
    setHtmlCode(INITIAL_SAMPLE_HTML);
    setHtmlFileName('index.html');
    setJsCode(INITIAL_SAMPLE_JS);
    setJsFileName('script.js');
    setOutputFileName('{{filehash}}.html');
    setResult(null);
  };

  const handleOpenDetections = (profileId: string) => {
    setActiveDetectionProfileId(profileId);
    setActiveView('detections');
  };

  const canExecute = Boolean(htmlCode.trim() && jsCode.trim());

  // Execute compiler matrix: 1 HTML + 1 JS -> 1 HTML output directly in browser
  const handleExecute = async () => {
    if (!canExecute || isExecuting) return;

    setIsExecuting(true);
    setResult(null);

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
        onNavigate={setActiveView}
      />

      {/* Main Workspace Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-3 sm:p-6 flex flex-col">
        {activeView === 'detections' ? (
          <DetectionSpecsPage
            profiles={profiles}
            initialProfileId={activeDetectionProfileId}
            onBackToCompiler={() => setActiveView('compiler')}
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

            {/* Two-column Layout: Dedicated Upload Fields on Left, Output Console on Right */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 items-start">
              {/* Left Column: Dedicated Upload Fields (No Pasting, No View Code Buttons) */}
              <div className="lg:col-span-5 flex flex-col gap-4">
                {/* 1. HTML Upload Dropzone Card */}
                <div className="w-full">
                  <HtmlUploadCard
                    value={htmlCode}
                    fileName={htmlFileName}
                    onFileLoaded={(content, name) => {
                      setHtmlCode(content);
                      setHtmlFileName(name);
                    }}
                    onClear={() => {
                      setHtmlCode('');
                      setHtmlFileName('');
                    }}
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
                    }}
                    onClear={() => {
                      setJsCode('');
                      setJsFileName('');
                    }}
                  />
                </div>
              </div>

              {/* Right Column: Execution Output (1 HTML output with live preview & download) */}
              <div className="lg:col-span-7 flex flex-col">
                <ExecutionConsoleCard
                  result={result}
                  isExecuting={isExecuting}
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
