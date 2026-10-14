// SPDX-License-Identifier: AGPL-3.0-or-later

export interface RegexDetection {
  id: string;
  name: string;
  pattern: string;
  flags: string;
  flavor: 'PCRE' | 'ECMAScript' | 'RE2' | 'Snort/Suricata';
  description: string;
  sampleMatch: string;
}

export interface ProfileDetectionSpec {
  profileId: string;
  profileLabel: string;
  title: string;
  category: string;
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH';
  mitreTechnique: string;
  mitreTactics: string[];
  summary: string;
  yaraRule: {
    ruleName: string;
    description: string;
    code: string;
  };
  regexDetections: RegexDetection[];
  siemDetections: {
    platform: 'Sigma' | 'Splunk' | 'Elasticsearch';
    query: string;
  }[];
  mitigationAdvice: string;
}

export const PROFILE_DETECTION_SPECS: Record<string, ProfileDetectionSpec> = {
  bundler: {
    profileId: 'bundler',
    profileLabel: 'Standard Standalone Bundler',
    title: 'Monolithic Inlined HTML-JS Payload Detection',
    category: 'Client-Side Infiltration / Script Bundling',
    severity: 'MEDIUM',
    mitreTechnique: 'T1059.007',
    mitreTactics: ['Execution', 'Defense Evasion'],
    summary:
      'Detects HTML documents with inlined monolithic JavaScript code blocks concatenated directly into DOM termination boundaries or template delimiters without external script references.',
    yaraRule: {
      ruleName: 'Exploit_Script_Bundler_HTML_Injection',
      description: 'Identifies monolithic HTML files compiled via direct script inlining and bundler timestamp banners',
      code: `rule Exploit_Script_Bundler_HTML_Injection
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects standalone HTML artifacts containing bundled JavaScript injection payloads"
        severity = "MEDIUM"
        mitre_technique = "T1059.007"
        date = "2026-10-11"
        license = "AGPL-3.0-or-later"

    strings:
        $html_doctype = "<!DOCTYPE html>" nocase
        $html_body    = "</body>" nocase
        $script_open  = "<script type=\\"text/javascript\\">" nocase
        $bundler_tag1 = "/* Bundled at " ascii
        $bundler_tag2 = "<!-- INJECT_JS -->" ascii
        $bundler_tag3 = "<!-- SCRIPT -->" ascii

    condition:
        filesize < 25MB and
        $html_doctype and
        $html_body and
        $script_open and
        (any of ($bundler_tag*))
}`,
    },
    regexDetections: [
      {
        id: 'bundler-timestamp-comment',
        name: 'Bundler Timestamp Comment Signature',
        pattern: '<script[^>]*>\\s*/\\*\\s*Bundled at \\d{4}-\\d{2}-\\d{2}T[0-9:.]+Z?\\s*\\*/',
        flags: 'is',
        flavor: 'PCRE',
        description: 'Matches the standardized timestamp banner prepended to inlined JavaScript payload blocks.',
        sampleMatch: '<script type="text/javascript">\n/* Bundled at 2026-10-11T12:00:00Z */\nconsole.log(1);',
      },
      {
        id: 'bundler-terminal-body-injection',
        name: 'Terminal Body Monolithic Script Block',
        pattern: '<script\\s+type=["\']text/javascript["\']>[\\s\\S]{300,}</script>\\s*</body>',
        flags: 'i',
        flavor: 'PCRE',
        description: 'Detects heavy inlined JavaScript (>300 chars) appended immediately adjacent to the closing body tag.',
        sampleMatch: '<script type="text/javascript">\nvar payload = "..."\n</script>\n</body>',
      },
      {
        id: 'bundler-template-marker',
        name: 'Residual Template Insertion Marker',
        pattern: '<!--\\s*(?:INJECT_JS|SCRIPT)\\s*-->',
        flags: 'i',
        flavor: 'Snort/Suricata',
        description: 'Detects unparsed or residual bundler hook comments in HTML stream transmissions.',
        sampleMatch: '<!-- INJECT_JS -->',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Inlined Script Bundler HTML Artifact Delivery
status: production
logsource:
    category: webserver
    product: proxy
detection:
    selection:
        http.response.body|contains:
            - '<script type="text/javascript">'
            - '/* Bundled at '
        http.response.content_type: 'text/html'
    condition: selection
level: medium`,
      },
      {
        platform: 'Splunk',
        query: `index=proxy sourcetype=access_combined status=200 http_content_type="text/html*"
| rex field=_raw "<script[^>]*>\\s*/\\*\\s*Bundled at (?<bundle_time>[^\\*]+)\\*/"
| where isnotnull(bundle_time)
| table _time, clientip, uri, bundle_time`,
      },
    ],
    mitigationAdvice:
      'Enforce external script loading via integrity-pinned subresource hashes (SRI). Disallow inline scripts in production environments using a Content-Security-Policy header omitting "unsafe-inline".',
  },

  hardener: {
    profileId: 'hardener',
    profileLabel: 'Security Hardened Assembler',
    title: 'Synthetic Content Security Policy Hash Injection Detection',
    category: 'Policy Manipulation / Integrity Bypass',
    severity: 'LOW',
    mitreTechnique: 'T1562.001',
    mitreTactics: ['Defense Evasion'],
    summary:
      'Detects HTML artifacts containing synthetic meta Content-Security-Policy directives with pre-computed sha256 inline nonces configured to allow restricted script execution.',
    yaraRule: {
      ruleName: 'Web_App_Hardened_CSP_Nonce_Injection',
      description: 'Matches HTML documents bearing synthetic CSP meta tags calculating script-src sha256 hashes',
      code: `rule Web_App_Hardened_CSP_Nonce_Injection
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects synthetic CSP meta policies with sha256 script hashing"
        severity = "LOW"
        mitre_technique = "T1562.001"
        date = "2026-10-11"
        license = "AGPL-3.0-or-later"

    strings:
        $meta_csp   = "<meta http-equiv=\\"Content-Security-Policy\\"" nocase
        $csp_src    = "script-src " nocase
        $csp_sha256 = "'sha256-" ascii
        $csp_strict = "'strict-dynamic'" nocase
        $script_tag = "<script type=\\"text/javascript\\"" nocase

    condition:
        filesize < 25MB and
        $meta_csp and
        $csp_src and
        $csp_sha256 and
        $script_tag
}`,
    },
    regexDetections: [
      {
        id: 'hardener-csp-sha256-meta',
        name: 'CSP Meta Tag with Inline SHA-256 Digest',
        pattern: '<meta\\s+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\'][^"\']*script-src[^"\']*\'sha256-[A-Za-z0-9+/=]{44}\'',
        flags: 'is',
        flavor: 'PCRE',
        description: 'Detects inlined Content Security Policy meta tags whitelisting specific script SHA-256 base64 digests.',
        sampleMatch: '<meta http-equiv="Content-Security-Policy" content="script-src \'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\' \'strict-dynamic\';">',
      },
      {
        id: 'hardener-assembler-comment',
        name: 'Hardened Assembler Metadata Comment',
        pattern: '<!--\\s*Hardened by Security Assembler\\s*-->',
        flags: 'i',
        flavor: 'Snort/Suricata',
        description: 'Matches the assembler signature comment stamped by the security hardener engine.',
        sampleMatch: '<!-- Hardened by Security Assembler -->',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Suspicious Client-Side CSP Meta Tag Modification
status: production
logsource:
    category: webserver
detection:
    selection:
        response.body|contains:
            - '<meta http-equiv="Content-Security-Policy"'
            - 'script-src'
            - "'sha256-"
    condition: selection
level: low`,
      },
    ],
    mitigationAdvice:
      'Serve Content-Security-Policy exclusively via HTTP response headers from verified edge proxies rather than client-controlled <meta> tags in HTML markup.',
  },

  sandbox: {
    profileId: 'sandbox',
    profileLabel: 'Interactive Test Harness',
    title: 'Client-Side Telemetry Interception & Debugger Hooking Detection',
    category: 'Telemetry Interception / Runtime Hooking',
    severity: 'MEDIUM',
    mitreTechnique: 'T1056.004',
    mitreTactics: ['Collection', 'Discovery'],
    summary:
      'Detects code instrumentation that proxies window.console, captures browser events into in-memory queues, or executes debugging telemetry harnesses.',
    yaraRule: {
      ruleName: 'JS_Harness_Telemetry_Interceptor_Sandbox',
      description: 'Detects client-side JavaScript hooking window.console and buffering telemetry output',
      code: `rule JS_Harness_Telemetry_Interceptor_Sandbox
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects runtime console interception and debugging telemetry queues"
        severity = "MEDIUM"
        mitre_technique = "T1056.004"
        date = "2026-10-11"
        license = "AGPL-3.0-or-later"

    strings:
        $hook_log   = "console.log = function" ascii
        $hook_apply = "apply(console, arguments)" ascii
        $telem_var  = "__drjekyll_telemetry" ascii
        $telem_alt  = "__telemetry_events" ascii
        $err_hook   = "window.addEventListener('error'" ascii

    condition:
        filesize < 15MB and
        ($hook_log or $hook_apply) and
        ($telem_var or $telem_alt or $err_hook)
}`,
    },
    regexDetections: [
      {
        id: 'sandbox-console-interceptor',
        name: 'Console Method Proxy Interceptor',
        pattern: 'console\\.(?:log|warn|error|info)\\s*=\\s*(?:function|\\([^)]*\\)\\s*=>)[^{]*\\{[^}]*(?:__telemetry|__drjekyll|apply\\(console)',
        flags: 'is',
        flavor: 'PCRE',
        description: 'Detects monkey-patching of native browser console output methods into telemetry collections.',
        sampleMatch: 'console.log = function() { window.__drjekyll_telemetry.push(arguments); };',
      },
      {
        id: 'sandbox-telemetry-queue',
        name: 'Global Telemetry Queue Allocation',
        pattern: 'window\\.(?:__drjekyll_telemetry|__harness_events)\\s*=\\s*\\[\\]',
        flags: 'i',
        flavor: 'ECMAScript',
        description: 'Detects global array buffers created for script output interception.',
        sampleMatch: 'window.__drjekyll_telemetry = [];',
      },
    ],
    siemDetections: [
      {
        platform: 'Splunk',
        query: `index=edr process_name IN ("chrome.exe", "msedge.exe", "firefox.exe")
| search "window.__drjekyll_telemetry" OR "console.log = function"
| stats count by host, user, process_name`,
      },
    ],
    mitigationAdvice:
      'Freeze native prototypes (Object.freeze(console)) early in execution context to prevent runtime API hooking or telemetry harvesting.',
  },

  injector: {
    profileId: 'injector',
    profileLabel: 'Dynamic Template & State Injector',
    title: 'Template Token Delimiter Hydration Payload Detection',
    category: 'Server-Side / Client-Side Template Injection',
    severity: 'MEDIUM',
    mitreTechnique: 'T1059.007',
    mitreTactics: ['Initial Access', 'Execution'],
    summary:
      'Detects dynamic injection targeting template placeholders ({{APP_SCRIPT}}, <!-- MOUNT_SCRIPT -->) used to hydrate web pages with client payloads.',
    yaraRule: {
      ruleName: 'Web_Template_Token_State_Injector',
      description: 'Detects unescaped template tags or dynamic state hydration script tags',
      code: `rule Web_Template_Token_State_Injector
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects template placeholders and state injection tags in HTML documents"
        severity = "MEDIUM"
        mitre_technique = "T1059.007"
        date = "2026-10-11"
        license = "AGPL-3.0-or-later"

    strings:
        $token1 = "{{APP_SCRIPT}}" ascii
        $token2 = "<!-- MOUNT_SCRIPT -->" ascii
        $token3 = "{{INJECTED_PAYLOAD}}" ascii
        $state1 = "<script id=\\"injected-template-state\\"" nocase
        $state2 = "data-injected-script" nocase

    condition:
        filesize < 25MB and (any of ($token*) or any of ($state*))
}`,
    },
    regexDetections: [
      {
        id: 'injector-raw-tokens',
        name: 'Template Placeholder Delimiter',
        pattern: '\\{\\{(?:APP_SCRIPT|INJECTED_PAYLOAD|DYNAMIC_STATE|BOOTSTRAP_CODE)\\}\\}',
        flags: 'i',
        flavor: 'RE2',
        description: 'Identifies unpopulated template delimiter tokens prone to injection replacement.',
        sampleMatch: '<div>{{APP_SCRIPT}}</div>',
      },
      {
        id: 'injector-comment-delimiters',
        name: 'HTML Mount Comment Token',
        pattern: '<!--\\s*(?:MOUNT_SCRIPT|INJECT_STATE|HYDRATE_APP)\\s*-->',
        flags: 'i',
        flavor: 'Snort/Suricata',
        description: 'Matches HTML comment targets used as mount boundaries for injected scripts.',
        sampleMatch: '<!-- MOUNT_SCRIPT -->',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Dynamic Template Token Injection Pattern
status: production
logsource:
    category: webserver
detection:
    selection:
        http.request.body|contains:
            - '{{APP_SCRIPT}}'
            - '<!-- MOUNT_SCRIPT -->'
    condition: selection
level: medium`,
      },
    ],
    mitigationAdvice:
      'Utilize context-aware contextual escaping parsers and strict template compilers rather than regex-based string replacements to avoid template injection.',
  },

  canonical: {
    profileId: 'canonical',
    profileLabel: 'Canonical Core Runner',
    title: 'Canonical Concatenation & End-of-Stream Payload Detection',
    category: 'Stream Concatenation / Payload Stamping',
    severity: 'LOW',
    mitreTechnique: 'T1059.007',
    mitreTactics: ['Execution'],
    summary:
      'Detects standard canonical single-file compilation where standalone JavaScript is appended at end-of-stream with canonical headers.',
    yaraRule: {
      ruleName: 'HTML_JS_Canonical_Core_Artifact',
      description: 'Matches canonical stream-appended JavaScript code blocks in HTML artifacts',
      code: `rule HTML_JS_Canonical_Core_Artifact
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects canonical single-file HTML-JS composite payloads"
        severity = "LOW"
        mitre_technique = "T1059.007"
        date = "2026-10-11"
        license = "AGPL-3.0-or-later"

    strings:
        $doctype = "<!DOCTYPE html>" nocase
        $closing = "</html>" nocase
        $sig1    = "<!-- CANONICAL_BUNDLE" ascii
        $sig2    = "data-compiler=\\"jekyll\\"" ascii
        $script  = "<script type=\\"text/javascript\\">" nocase

    condition:
        filesize < 25MB and
        $doctype and
        $closing and
        $script and
        (any of ($sig*))
}`,
    },
    regexDetections: [
      {
        id: 'canonical-signature-stamp',
        name: 'Canonical Compiler Signature Stamp',
        pattern: '<!--\\s*CANONICAL_BUNDLE_[A-Z0-9_]+\\s*-->',
        flags: 'i',
        flavor: 'Snort/Suricata',
        description: 'Detects the unique canonical signature block stamped onto compiled output bundles.',
        sampleMatch: '<!-- CANONICAL_BUNDLE_V1 -->',
      },
      {
        id: 'canonical-tail-injection',
        name: 'Tail Script Stream Concatenation',
        pattern: '<script\\s+type=["\']text/javascript["\']>[^<]{150,}</script>\\s*</html>',
        flags: 'is',
        flavor: 'PCRE',
        description: 'Matches raw JavaScript payload blocks appended immediately prior to the closing html tag.',
        sampleMatch: '<script type="text/javascript">\nvar core = 1;\n</script>\n</html>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Canonical Composite HTML-JS Payload Detection
status: production
logsource:
    category: webserver
detection:
    selection:
        http.response.body|contains:
            - '<!-- CANONICAL_BUNDLE'
            - '<script type="text/javascript">'
    condition: selection
level: low`,
      },
    ],
    mitigationAdvice:
      'Separate static presentation markup from dynamic code execution; serve scripts through secure authenticated CDNs with SRI hashing.',
  },
};
