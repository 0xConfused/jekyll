// SPDX-License-Identifier: AGPL-3.0-or-later

export const DEFAULT_SAMPLE_HTML = `<!DOCTYPE html>
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
    #target-area {
      margin-top: 16px;
      padding: 12px;
      background: #0d0d0d;
      border: 1px solid #2e2e2e;
      color: #8c8c8c;
      font-size: 11px;
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

    <div id="target-area">
      Awaiting script payload integration...
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

export const DEFAULT_SAMPLE_JS = `// Verification Script Payload
(function verifyPayloadExecution() {
  function applyStatus(success, message, details) {
    var card = document.getElementById('status-card');
    var indicator = document.getElementById('status-indicator');
    var title = document.getElementById('status-title');
    var msg = document.getElementById('status-message');
    var telemetry = document.getElementById('telemetry-data');
    var target = document.getElementById('target-area');
    var panel = document.querySelector('.panel');

    if (card) {
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

    if (target) {
      target.textContent = success
        ? 'Status: Subsystem active. Injected script is executing and responding in DOM.'
        : 'Status: Subsystem execution failed.';
      target.style.color = success ? '#bbc300' : '#c3005a';
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

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    run();
  } else {
    document.addEventListener('DOMContentLoaded', run);
    window.addEventListener('load', run);
    setTimeout(run, 0);
  }
})();`;
