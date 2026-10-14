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
  <title>Execution Verification Host</title>
  <style>
    body {
      background: #0d0d0d;
      color: #f0f0f0;
      font-family: 'Fira Code', monospace, sans-serif;
      margin: 0;
      padding: 24px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      box-sizing: border-box;
    }
    .panel {
      background: #141414;
      border: 1px solid #383838;
      border-top: 3px solid #c3005a;
      padding: 24px;
      max-width: 580px;
      width: 100%;
      box-sizing: border-box;
      transition: border-color 0.3s ease;
    }
    h1 {
      font-size: 13px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin: 0 0 16px 0;
      color: #8c8c8c;
      border-bottom: 1px solid #2e2e2e;
      padding-bottom: 10px;
    }
    #status-card {
      padding: 16px;
      background: #1a1a1a;
      border: 1px solid #c3005a;
      transition: all 0.3s ease;
    }
    #status-indicator {
      display: inline-block;
      width: 8px;
      height: 8px;
      background: #c3005a;
      margin-right: 8px;
    }
    #status-title {
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: #c3005a;
    }
    #status-message {
      margin-top: 10px;
      font-size: 12px;
      line-height: 1.5;
      color: #8c8c8c;
    }
    #telemetry-data {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid #2e2e2e;
      font-size: 11px;
      color: #737373;
    }
    .carrier-container {
      margin-top: 16px;
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      background: #0d0d0d;
      border: 1px solid #2e2e2e;
      font-size: 11px;
      color: #737373;
    }
    .carrier-container img {
      width: 32px;
      height: 32px;
      border: 1px solid #383838;
      background: #1a1a1a;
    }
  </style>
</head>
<body>
  <div class="panel">
    <h1>HOST EXECUTION VERIFICATION</h1>
    <div id="status-card">
      <div style="display: flex; align-items: center;">
        <span id="status-indicator"></span>
        <span id="status-title">STATUS: [ FAIL ]</span>
      </div>
      <div id="status-message">
        Script execution not detected. The payload has either failed to run, was blocked, or has not yet been executed by the host container.
      </div>
      <div id="telemetry-data">
        Timestamp: Pending execution verification...
      </div>
    </div>

    <!-- Carrier Image: Provides anchor for steganographic and polyglot injection engines -->
    <div class="carrier-container">
      <img id="host-carrier-img" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAWUlEQVRYR+2WwQkAMAhD6790F3WCOkEFPxJ40EtJ85o5s11n9m6Bq/4tA3oG9Azov0Avw8m90DOgZ0DPgJ4BPQN6BvQM6BnQM6BnQM+AngE9A3oG9Az8nIEP2l73E2wMsqEAAAAASUVORK5CYII=" alt="Carrier Image" />
      <div>
        <div style="color: #f0f0f0; font-weight: 600;">Host Carrier Node</div>
        <div>DOM anchor for image-based and steganographic injection engines</div>
      </div>
    </div>
  </div>
</body>
</html>`;

const INITIAL_SAMPLE_JS = `// Verification Script Payload
(function verifyPayloadExecution() {
  function applyStatus(success, message, details) {
    var card = document.getElementById('status-card');
    var indicator = document.getElementById('status-indicator');
    var title = document.getElementById('status-title');
    var msg = document.getElementById('status-message');
    var telemetry = document.getElementById('telemetry-data');
    var panel = document.querySelector('.panel');

    if (!card) {
      console.warn('[VERIFICATION] Host status container not found in DOM.');
      return;
    }

    if (success) {
      card.style.borderColor = '#bbc300';
      card.style.background = '#141414';
      if (panel) panel.style.borderTopColor = '#bbc300';
      if (indicator) {
        indicator.style.background = '#bbc300';
      }
      if (title) {
        title.style.color = '#bbc300';
        title.textContent = 'STATUS: [ SUCCESS ]';
      }
      if (msg) {
        msg.style.color = '#f0f0f0';
        msg.textContent = message || 'Script executed successfully. Injected logic is active and operational in global scope.';
      }
      if (telemetry) {
        telemetry.style.color = '#8c8c8c';
        telemetry.textContent = 'Verified At: ' + new Date().toISOString() + (details ? ' // ' + details : '');
      }

      // Append interactive verification control if not already present
      if (!document.getElementById('pulse-btn')) {
        var btn = document.createElement('button');
        btn.id = 'pulse-btn';
        btn.textContent = 'DISPATCH PULSE';
        btn.style.marginTop = '12px';
        btn.style.padding = '6px 14px';
        btn.style.background = '#c30800';
        btn.style.color = '#f3f3f7';
        btn.style.border = '1px solid #383838';
        btn.style.cursor = 'pointer';
        btn.style.fontFamily = 'monospace';
        btn.style.fontSize = '11px';
        btn.style.fontWeight = 'bold';

        var pulses = 0;
        btn.onclick = function() {
          pulses++;
          if (telemetry) {
            telemetry.textContent = 'Pulses Dispatched: ' + pulses + ' // Last: ' + new Date().toISOString();
          }
        };
        card.appendChild(btn);
      }
    } else {
      card.style.borderColor = '#c3005a';
      card.style.background = '#1a1a1a';
      if (panel) panel.style.borderTopColor = '#c3005a';
      if (indicator) {
        indicator.style.background = '#c3005a';
      }
      if (title) {
        title.style.color = '#c3005a';
        title.textContent = 'STATUS: [ FAIL ]';
      }
      if (msg) {
        msg.style.color = '#f0f0f0';
        msg.textContent = message || 'Runtime error during script execution.';
      }
      if (telemetry) {
        telemetry.style.color = '#c3005a';
        telemetry.textContent = 'Error: ' + (details || 'Unknown exception');
      }
    }
  }

  function run() {
    try {
      var token = Math.floor(Math.random() * 100000).toString(16);
      applyStatus(
        true,
        'Script executed successfully. Injected payload runtime is active and responsive.',
        'Execution Token: 0x' + token
      );
    } catch (err) {
      applyStatus(
        false,
        'Script failed with exception: ' + (err && err.message ? err.message : String(err)),
        'Exception occurred during payload initialization'
      );
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();`;

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
