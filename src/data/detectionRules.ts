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
  'url-matrix': {
    profileId: 'url-matrix',
    profileLabel: 'URL String Matrix',
    title: 'Node.js Documentation URL Matrix Obfuscation Detection',
    category: 'Defense Evasion / String Character Mapping',
    severity: 'HIGH',
    mitreTechnique: 'T1027',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads decomposed into character coordinates mapped onto literal Node.js documentation URL strings and reconstituted in memory via Function constructor.',
    yaraRule: {
      ruleName: 'Exploit_URL_Matrix_Obfuscator',
      description: 'Identifies scripts reconstituting payloads via Node.js API documentation URL index lookups',
      code: `rule Exploit_URL_Matrix_Obfuscator
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects URL matrix string decomposition payloads"
        severity = "HIGH"
        mitre_technique = "T1027"
        date = "2026-10-14"
        license = "AGPL-3.0-or-later"

    strings:
        $nodejs_url1 = "https://nodejs.org/api/crypto.html" ascii
        $nodejs_url2 = "https://nodejs.org/api/querystring.html" ascii
        $unpack_loop = "while(i<_f.length)" ascii
        $char_code   = "charCodeAt" ascii
        $func_exec   = "new Function(_p)" ascii

    condition:
        filesize < 25MB and
        ($nodejs_url1 or $nodejs_url2) and
        $unpack_loop and
        $func_exec
}`,
    },
    regexDetections: [
      {
        id: 'url-matrix-url-dataset',
        name: 'Node.js Documentation URL Dataset Array',
        pattern: `const\\s+_d\\s*=\\s*\\["https:\\/\\/nodejs\\.org\\/api\\/crypto\\.html"`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Matches the characteristic Node.js URL matrix array definition header.',
        sampleMatch: 'const _d=["https://nodejs.org/api/crypto.html","https://nodejs.org/api/querystring.html"',
      },
      {
        id: 'url-matrix-unpack-routine',
        name: 'Matrix Byte Unpacking and Function Execution',
        pattern: `new\\s+Function\\(_p\\)\\(\\);\\}\\s*catch\\(e\\)\\{console\\.error\\("Matrix corrupted\\."`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Identifies the execution block compiling and invoking the reconstituted payload.',
        sampleMatch: 'new Function(_p)();}catch(e){console.error("Matrix corrupted.",e)}}());',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Suspicious Node.js URL Character Matrix Script
status: experimental
description: Detects HTML documents containing Node.js URL matrix character mapping payloads
logsource:
  category: web_content
detection:
  selection:
    Content|contains:
      - 'https://nodejs.org/api/crypto.html'
      - 'new Function(_p)'
  condition: selection`,
      },
    ],
    mitigationAdvice:
      'Enforce strict Content Security Policy (CSP) headers without unsafe-eval. Disable runtime Dynamic Code Generation (script-src without unsafe-eval).',
  },

  'html-char-packer': {
    profileId: 'html-char-packer',
    profileLabel: 'HTML Charset Packer',
    title: 'HTML Harvesting Character Index Repacker Detection',
    category: 'Defense Evasion / Dynamic Decoding',
    severity: 'HIGH',
    mitreTechnique: 'T1027',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads encoded into base-93 index streams reconstituted at runtime from character sets harvested from the surrounding HTML document and evaluated via indirect eval.',
    yaraRule: {
      ruleName: 'Exploit_HTML_Charset_Packer',
      description: 'Matches HTML-harvested character index unpacking routines',
      code: `rule Exploit_HTML_Charset_Packer
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects HTML charset index unpacking routines"
        severity = "HIGH"
        mitre_technique = "T1027"
        date = "2026-10-14"
        license = "AGPL-3.0-or-later"

    strings:
        $unpacker_hdr  = "var C=" ascii
        $unpacker_vars = ",P=" ascii
        $unpacker_w    = ",W=" ascii
        $indirect_eval = "(0,eval)(o)" ascii
        $char_marker   = "!\"&&k!=\"#\"" ascii

    condition:
        filesize < 25MB and
        $unpacker_hdr and
        $unpacker_vars and
        $indirect_eval
}`,
    },
    regexDetections: [
      {
        id: 'char-packer-unpack-template',
        name: 'HTML Charset Unpack Routine Header',
        pattern: `<script>\\(function\\(\\)\\{var C=.*?,P=.*?,W=\\d+,D=\\{\\}`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Detects the inlined unpacker function header initializing charset C and packed stream P.',
        sampleMatch: '<script>(function(){var C="<!DOCTYPE...",P="!...#...",W=1,D={},n=0',
      },
      {
        id: 'char-packer-indirect-eval',
        name: 'Global Scope Indirect Eval Invocator',
        pattern: `\\(0,eval\\)\\(o\\)\\}\\)\\(\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Matches the global scope indirect eval execution pattern terminating the unpacker.',
        sampleMatch: '(0,eval)(o)})()',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: In-Memory Indirect Eval Script Unpacker
status: experimental
description: Detects HTML documents executing scripts via indirect global eval
logsource:
  category: web_content
detection:
  selection:
    Content|contains:
      - '(0,eval)(o)'
      - 'W='
  condition: selection`,
      },
    ],
    mitigationAdvice:
      'Disable unsafe-eval in Content Security Policy (CSP). Implement static application security testing to detect unminified character harvest packing routines.',
  },

  'hidden-img-xor': {
    profileId: 'hidden-img-xor',
    profileLabel: 'Hidden Image XOR',
    title: 'Camouflaged Image XOR Payload and Onload Injection Detection',
    category: 'Defense Evasion / Steganography / Inline Loader',
    severity: 'HIGH',
    mitreTechnique: 'T1027.003',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads XOR-encrypted with a JPEG header key hidden inside an invisible image element and executed via a randomly placed onload attribute.',
    yaraRule: {
      ruleName: 'Exploit_Hidden_Img_XOR_Loader',
      description: 'Identifies invisible images carrying base64 XOR payloads with onload attributes',
      code: `rule Exploit_Hidden_Img_XOR_Loader
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects hidden image XOR payloads and onload execution"
        severity = "HIGH"
        mitre_technique = "T1027.003"
        date = "2026-10-14"
        license = "AGPL-3.0-or-later"

    strings:
        $data_jpeg   = "data:image/jpeg;base64," ascii nocase
        $onload_tok  = "onload=" ascii nocase
        $text_dec    = "TextDecoder().decode" ascii
        $func_exec   = "Function(new TextDecoder()" ascii

    condition:
        filesize < 25MB and
        $data_jpeg and
        $onload_tok and
        ($text_dec or $func_exec)
}`,
    },
    regexDetections: [
      {
        id: 'hidden-img-xor-loader',
        name: 'Onload XOR Decoder and TextDecoder Function Routine',
        pattern: `onload="setTimeout\\(\\(\\)=>\\{let a=Uint8Array\\.from\\(atob\\(`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Identifies the inline onload attribute executing atob extraction and TextDecoder instantiation.',
        sampleMatch: 'onload="setTimeout(()=>{let a=Uint8Array.from(atob(img_a1b2.src.split(\',\')[1])',
      },
      {
        id: 'hidden-img-hidden-css',
        name: 'Stealth Image Attribute with Concealed Bounds',
        pattern: `<img\\s+id="img_[a-f0-9]+"[^>]*style="[^"]*(?:clip-path:inset|position:absolute;left:-9999px|width:0;height:0)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Matches concealed image DOM tags created to hide base64 payload carriers.',
        sampleMatch: '<img id="img_e3f2" src="data:image/jpeg;base64,..." style="clip-path:inset(100%)">',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Suspicious Inline Onload Atob Loader in HTML
status: experimental
description: Detects onload attributes executing inline atob base64 decoders
logsource:
  category: web_content
detection:
  selection:
    Content|contains:
      - 'data:image/jpeg;base64,'
      - 'TextDecoder().decode'
  condition: selection`,
      },
    ],
    mitigationAdvice:
      'Prohibit inline event handlers using Content Security Policy (disallow unsafe-inline). Sanitize DOM attributes to eliminate dynamic onload execution.',
  },

  'lsb-stego': {
    profileId: 'lsb-stego',
    profileLabel: 'Image LSB Steganography',
    title: 'Least Significant Bit (LSB) Canvas Steganography Detection',
    category: 'Defense Evasion / Image Steganography',
    severity: 'MEDIUM',
    mitreTechnique: 'T1027.003',
    mitreTactics: ['Defense Evasion'],
    summary:
      'Detects code concealed within the least significant bits of image pixel color channels, coupled with client-side HTML5 canvas getImageData extraction routines.',
    yaraRule: {
      ruleName: 'Exploit_LSB_Canvas_Stego_Extractor',
      description: 'Detects HTML5 canvas getImageData extraction loops reading image LSB bits',
      code: `rule Exploit_LSB_Canvas_Stego_Extractor
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects canvas LSB pixel bit extraction onload scripts"
        severity = "MEDIUM"
        mitre_technique = "T1027.003"
        date = "2026-10-14"
        license = "AGPL-3.0-or-later"

    strings:
        $canvas_ctx  = "getContext(\`2d\`)" ascii
        $get_data    = "getImageData" ascii
        $bit_shift   = "b=b*2+d[p+k]%2" ascii
        $eval_unesc  = "eval(decodeURIComponent(escape(" ascii

    condition:
        filesize < 25MB and
        $canvas_ctx and
        $get_data and
        $bit_shift
}`,
    },
    regexDetections: [
      {
        id: 'lsb-stego-canvas-extractor',
        name: 'Canvas LSB Bit Accumulation Loop',
        pattern: `for\\(let p=0;p<d\\.length;p\\+=4\\)for\\(let k of \\[.*?\\]\\)\\{b=b\\*2\\+d\\[p\\+k\\]%2;`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Matches the pixel buffer traversal extracting parity bits across color channels.',
        sampleMatch: 'for(let p=0;p<d.length;p+=4)for(let k of [0,1,2]){b=b*2+d[p+k]%2;',
      },
      {
        id: 'lsb-stego-onload-attr',
        name: 'Onload Natural Dimensions Canvas Extractor',
        pattern: `onload="let t=this,c=document\\.createElement\\(\`canvas\`\\),x=c\\.getContext\\(\`2d\`\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Identifies the inline onload attribute mounting the hidden extraction canvas.',
        sampleMatch: 'onload="let t=this,c=document.createElement(`canvas`),x=c.getContext(`2d`)',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Canvas Pixel Data Extraction via Inline Onload
status: experimental
description: Detects inline image onload attributes using 2D canvas pixel data extraction
logsource:
  category: web_content
detection:
  selection:
    Content|contains:
      - 'getImageData'
      - 'naturalWidth'
      - 'eval(decodeURIComponent'
  condition: selection`,
      },
    ],
    mitigationAdvice:
      'Strip unnecessary image onload handlers. Disallow eval through CSP script-src directives.',
  },

  'zip-appender': {
    profileId: 'zip-appender',
    profileLabel: 'ZIP Trailing-Data Appender',
    title: 'Image Polyglot Trailing ZIP Archive Detection',
    category: 'Defense Evasion / Polyglot File Append',
    severity: 'MEDIUM',
    mitreTechnique: 'T1027.001',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects polyglot image files containing appended ZIP archives beyond image trailer markers (IEND/EOI), unpacked dynamically in-browser via JSZip CDN loaders.',
    yaraRule: {
      ruleName: 'Exploit_Image_Trailing_ZIP_Polyglot',
      description: 'Detects base64 image data containing appended PK zip headers and JSZip unpackers',
      code: `rule Exploit_Image_Trailing_ZIP_Polyglot
{
    meta:
        author = "0xCONFUSED Cyber Operations"
        description = "Detects image files with appended ZIP payloads loaded via JSZip"
        severity = "MEDIUM"
        mitre_technique = "T1027.001"
        date = "2026-10-14"
        license = "AGPL-3.0-or-later"

    strings:
        $jszip_cdn   = "jszip.min.js" ascii nocase
        $iend_tag    = "IEND" ascii
        $load_async  = "JSZip.loadAsync" ascii

    condition:
        filesize < 25MB and
        $jszip_cdn and
        $load_async
}`,
    },
    regexDetections: [
      {
        id: 'zip-appender-jszip-script',
        name: 'JSZip CDN Script Tag Loader',
        pattern: `<script src="https:\\/\\/cdnjs\\.cloudflare\\.com\\/ajax\\/libs\\/jszip\\/[\\d\\.]+\\/jszip\\.min\\.js" onload=`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Matches the external script injection referencing JSZip with an unpacking onload callback.',
        sampleMatch: '<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js" onload=\'(async()=>{',
      },
      {
        id: 'zip-appender-finder-routine',
        name: 'Image Trailer Marker Finder Routine',
        pattern: `function F\\(b\\)\\{.*?if\\(t=="IEND"\\)return o;`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Detects the byte scanner locating the boundary where image data ends and the ZIP archive begins.',
        sampleMatch: 'function F(b){const v=new DataView(b.buffer);let o=8;while(o+8<=b.length){...if(t=="IEND")return o;}return -1;}',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Suspicious JSZip Polyglot Unpacker in Web Artifact
status: experimental
description: Detects HTML documents loading JSZip to unpack trailing image ZIP archives
logsource:
  category: web_content
detection:
  selection:
    Content|contains:
      - 'jszip.min.js'
      - 'JSZip.loadAsync'
  condition: selection`,
      },
    ],
    mitigationAdvice:
      'Restrict external CDN script loading via CSP script-src directives. Validate that uploaded or served image files do not contain trailing bytes beyond standard container format trailers.',
  },
};
