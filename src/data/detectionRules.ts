// SPDX-License-Identifier: AGPL-3.0-or-later

export interface RegexDetection {
  id: string;
  name: string;
  role: 'CARRIER_TERM' | 'CARGO_TERM' | 'DECODE_TERM' | 'SINK_TERM' | 'CONFLUENT_SUM';
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
  detectionStrategy: string;
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
  'dom-method-hook': {
    profileId: 'dom-method-hook',
    profileLabel: 'DOM Method Hooking',
    title: 'Common DOM Function Rebinding & Execution Hijacking Detection',
    category: 'Defense Evasion / Execution Hijacking',
    severity: 'HIGH',
    mitreTechnique: 'T1562.001',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects repeated common browser/DOM function names, rebinding, ===[1-9], map/forEach, try block, and dynamic execution sinks (eval, setTimeout, setInterval, Function).',
    detectionStrategy:
      'Evaluates HTML script elements for common DOM API rebinding and execution hijacking. Detects instances where standard DOM or browser methods are reassigned alongside strict parameter count inspection (===[1-9]) and iterated via .map() or .forEach() into try/catch blocks executing dynamic sinks or arrow wrappers within 800 bytes.',
    yaraRule: {
      ruleName: 'JS_Common_Function_Rebinding_Map_Execution',
      description:
        'Detects repeated common browser/DOM function names, rebinding, ===[1-9], map/forEach, try block, and dynamic execution',
      code: `rule JS_Common_Function_Rebinding_Map_Execution
{
    strings:
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateElement\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateElement\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementById\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementById\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelector\\b(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelector\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelectorAll\\b(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelectorAll\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateTextNode\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateTextNode\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByClassName\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByClassName\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByTagName\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByTagName\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByName\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByName\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttribute\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttribute\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttribute\\b(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttribute\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<t]*t)+oggleAttribute\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+oggleAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ddEventListener\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ddEventListener\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveEventListener\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveEventListener\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<d]*d)+ispatchEvent\\b(?:[^<]*<[^\\/])*(?:[^<d]*d)+ispatchEvent\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppendChild\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppendChild\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveChild\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveChild\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertBefore\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertBefore\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChild\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChild\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+loneNode\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+loneNode\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+ontains\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+ontains\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<m]*m)+atches\\b(?:[^<]*<[^\\/])*(?:[^<m]*m)+atches\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+losest\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+losest\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etRootNode\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etRootNode\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+ompareDocumentPosition\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+ompareDocumentPosition\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNode\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNode\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttributeNode\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttributeNode\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttributeNode\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttributeNode\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNames\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNames\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttributes\\b(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttributes\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ttachShadow\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ttachShadow\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentElement\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentElement\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentHTML\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentHTML\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentText\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentText\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<b]*b)+efore\\b(?:[^<]*<[^\\/])*(?:[^<b]*b)+efore\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+fter\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+fter\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceWith\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceWith\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emove\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emove\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<p]*p)+repend\\b(?:[^<]*<[^\\/])*(?:[^<p]*p)+repend\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppend\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppend\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChildren\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChildren\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<f]*f)+ocus\\b(?:[^<]*<[^\\/])*(?:[^<f]*f)+ocus\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<b]*b)+lur\\b(?:[^<]*<[^\\/])*(?:[^<b]*b)+lur\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+lick\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+lick\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+croll\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+croll\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollTo\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollTo\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollBy\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollBy\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollIntoView\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollIntoView\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etBoundingClientRect\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etBoundingClientRect\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etClientRects\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etClientRects\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+nimate\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+nimate\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etTimeout\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etTimeout\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etInterval\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etInterval\\s*=[^=](?:[^<]*<[^\\/])*(?:[^<=]*=)+==[1-9](?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i

    condition:
        for any of them : ($ and ! <= 500)
}`,
    },
    regexDetections: [
      {
        id: 'hook-script-carrier-term',
        name: 'HTML Host Script Carrier Term',
        role: 'CARRIER_TERM',
        pattern:
          '<script[^>]*>(?:[^<]*<[^\/])*(?:createElement|getElementById|querySelector|querySelectorAll|createTextNode|getElementsByClassName|getElementsByTagName|getElementsByName|getAttribute|setAttribute|hasAttribute|removeAttribute|toggleAttribute|addEventListener|removeEventListener|dispatchEvent|appendChild|removeChild|insertBefore|replaceChild|cloneNode|contains|matches|closest)\b',
        flags: 'gmi',
        flavor: 'ECMAScript',
        description:
          'Anchored on static <script; matches the HTML script envelope hosting common DOM or browser function declarations.',
        sampleMatch: '<script>const _create = document.createElement.bind(document);...',
      },
      {
        id: 'hook-dom-override-term',
        name: 'DOM Built-In Method Rebinding Assignment Term',
        role: 'DECODE_TERM',
        pattern:
          '(?:\b(?:createElement|getElementById|querySelector|querySelectorAll|createTextNode|getElementsByClassName|getElementsByTagName|getElementsByName|getAttribute|setAttribute|hasAttribute|removeAttribute|toggleAttribute|addEventListener|removeEventListener|dispatchEvent|appendChild|removeChild|insertBefore|replaceChild|cloneNode|contains|matches|closest)\b[\s\S]*?){2}=[^=]',
        flags: 'gmi',
        flavor: 'ECMAScript',
        description:
          'Detects repeated common browser/DOM function names followed by reassignment/rebinding without identity equality.',
        sampleMatch: 'document.createElement = (...a) => ...',
      },
      {
        id: 'hook-strict-arity-check',
        name: 'Strict Arity Inspection Term',
        role: 'DECODE_TERM',
        pattern: '={2,3}[1-9]',
        flags: 'gm',
        flavor: 'ECMAScript',
        description:
          'Detects strict equality checks against non-zero integers (===[1-9]) used to intercept specific argument lengths.',
        sampleMatch: 'a.length === 2 ? a.map(...) : _create(a[0])',
      },
      {
        id: 'hook-map-try-interceptor',
        name: 'Array Iteration & Error Trap Term',
        role: 'DECODE_TERM',
        pattern: '\\.(?:map|forEach)\\b[\\s\\S]*?try\\s*\\{',
        flags: 'gmi',
        flavor: 'ECMAScript',
        description:
          'Detects array traversal via .map or .forEach routing into a try-catch error handling block.',
        sampleMatch: 'a.map(v => { try { eval(v) } catch { ... } })',
      },
      {
        id: 'hook-dynamic-sink-term',
        name: 'Dynamic Execution Sink Term',
        role: 'SINK_TERM',
        pattern:
          "(?:\\b(?:eval|setTimeout|setInterval|Function)\\s*(?:\\[['\"`]\\w+['\"`]\\])?\\(|\\)\\s*=>\\s*\\{)",
        flags: 'gmi',
        flavor: 'ECMAScript',
        description:
          'Detects dynamic evaluation sinks (eval, setTimeout, setInterval, Function) or anonymous arrow handlers within the interceptor.',
        sampleMatch: 'try { eval(v) } catch { ... }',
      },
      {
        id: 'hook-compound-rule',
        name: 'Confluent Rebinding Map Execution Compound Rule (Sum of Terms)',
        role: 'CONFLUENT_SUM',
        pattern:
          '<script[^>]*>[\\s\\S]*?(?:createElement|getElementById|querySelector|getAttribute|addEventListener|appendChild)[\\s\\S]*?=[^=][\\s\\S]*?===[1-9][\\s\\S]*?\\.(?:map|forEach)\\b[\\s\\S]*?try\\s*\\{[\\s\\S]*?(?:eval|setTimeout|setInterval|Function|\\)\\s*=>\\s*\\{)',
        flags: 'gmi',
        flavor: 'ECMAScript',
        description:
          'Confluent sum of script carrier + function rebinding + ===[1-9] arity check + map/forEach + try block + dynamic sink within 800 bytes.',
        sampleMatch:
          '<script>...createElement...createElement = (...a) => a.length === 2 ? a.map(v => { try { eval(v) }...})...</script>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent Common Browser Function Rebinding and Map Execution Hijacking in HTML
status: experimental
description: Detects HTML scripts containing common DOM function rebinding, ===[1-9] arity check, map/forEach iteration, and dynamic execution
logsource:
  category: web_content
detection:
  selection_carrier:
    Content|contains: '<script'
  selection_hook:
    Content|re: '\\b(createElement|getElementById|querySelector|querySelectorAll|createTextNode|getAttribute|setAttribute|addEventListener|appendChild)\\b[\\s\\S]*?\\1\\s*='
  selection_arity:
    Content|re: '===[1-9]'
  selection_map_try:
    Content|re: '\\.(?:map|forEach)[\\s\\S]*?try\\s*\\{'
  selection_sink:
    Content|re: '(?:eval|setTimeout|setInterval|Function|\\)\\s*=>\\s*\\{)'
  condition: selection_carrier and selection_hook and selection_arity and selection_map_try and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Freeze global and prototype DOM methods using Object.freeze(Document.prototype) and Object.freeze(Element.prototype) to prevent runtime rebinding and prototype tampering.',
  },
  'image-onerror-xor': {
    profileId: 'image-onerror-xor',
    profileLabel: 'Image Onerror XOR Carrier',
    title: 'Concealed Image XOR Payload Extraction Detection',
    category: 'Defense Evasion / Stenographic Obfuscation',
    severity: 'HIGH',
    mitreTechnique: 'T1027.003',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads hidden in base64 data URIs of concealed <img> tags, extracted and unmasked via inline onerror event handlers with XOR operations, and executed dynamically.',
    detectionStrategy:
      'Evaluated against HTML documents. While standard HTML images frequently use base64 data URIs or zero-size styling in benign designs, combining concealed <img> tags with inline onload/onerror decoding, array XOR byte unmasking, and dynamic execution sinks (Function, setTimeout) offsets false positive risk and exposes payload delivery.',
    yaraRule: {
      ruleName: 'concealed_image_xor_payload',
      description: 'Detects hidden image XOR payloads in HTML',
      code: `rule concealed_image_xor_payload
{
    strings:
        $carrier_img_id=/<img\\b(?:[^\\/]*\\/[^>])*(?:[^\\x20\\/]*\\x20)+id=['"]/i
        $carrier_img_onerror=/<img\\b(?:[^\\/]*\\/[^>])*(?:[^\\x20\\/]*\\x20)+onerror=/i

        $decode_xor_loop=/\\^=?\\w+\\[\\w+%\\w+\\.length\\]/
        $decode_data_image=/<img\\b(?:[^\\/]*\\/[^>])*(?:[^\\x20\\/]*\\x20)+src=['"]data:image\\/[\\w-]+;base64,/i
        $decode_src_split=/\.src\.split\(['"\`],['"\`]\)\\[1\\]/

    condition:
        filesize < 25MB and
        any of ($carrier_img_*) and
        all of ($decode_*)
}`,
    },
    regexDetections: [
      {
        id: 'hidden-img-carrier-term',
        name: 'Concealed Carrier Image Tag Term',
        role: 'CARRIER_TERM',
        pattern: `<img\\s[\\s\\S]*?(?:width:\\s*0|height:\\s*0|display:\\s*none|opacity:\\s*0|left:\\s*-9999px|top:\\s*-100vh|visibility:\\s*hidden|clip-path)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <img; matches image elements concealed via CSS dimensions or clipping. Benign in isolation on tracking pixels.',
        sampleMatch: '<img src="data:image/png;base64,..." onerror="..." style="display:none">',
      },
      {
        id: 'hidden-img-data-cargo',
        name: 'Base64 Encoded Image Data Cargo Term',
        role: 'CARGO_TERM',
        pattern: `src=['"\`]data:image\\/(?:jpeg|png|webp);base64,[\\w+/=]{60,}['"\`]`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static src=data:image/; identifies base64-encoded image payloads carrying XOR-masked ciphertext.',
        sampleMatch: 'src="data:image/png;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBD..."',
      },
      {
        id: 'hidden-img-atob-extractor',
        name: 'Base64 Image Data Decoding Term',
        role: 'DECODE_TERM',
        pattern: `atob\\s*\\(\\s*(?:this\\.src|[$\\w]+)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static atob(; detects base64 decoding of the image data URI payload from element properties or variables.',
        sampleMatch: "atob(this.src.split(',')[1])",
      },
      {
        id: 'hidden-img-decode-term',
        name: 'XOR Bitwise Byte Unmasking Term',
        role: 'DECODE_TERM',
        pattern: `(?:b\\^k\\[i\\s*%\\s*k\\.length\\]|\\b[$\\w]+\\[[$\\w]+\\]\\s*\\^=)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static ^; detects array map or loop bitwise XOR operations decrypting concealed payload bytes.',
        sampleMatch: '((a,k)=>a.map((b,i)=>b^k[i%k.length]))',
      },
      {
        id: 'hidden-img-sink-term',
        name: 'Dynamic Execution Sink Term',
        role: 'SINK_TERM',
        pattern: `(?:Function|eval|setTimeout)\\s*\\(\\s*(?:String\\.fromCharCode|new\\s+TextDecoder)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on dynamic execution sinks; verifies that decoded character codes pass directly into Function or eval.',
        sampleMatch: 'Function(String.fromCharCode(...))',
      },
      {
        id: 'hidden-img-compound-rule',
        name: 'Confluent End-to-End Compound Rule (Sum of Terms)',
        role: 'CONFLUENT_SUM',
        pattern: `<img\\s+src=['"\`]data:image\\/[^;]+;base64,[\\s\\S]*?(?:onload|onerror)\\s*=\\s*['"\`][\\s\\S]*?(?:Function|eval|setTimeout)[\\s\\S]*?\\^[\\s\\S]*?atob`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <img; the sum of hidden image + onerror handler + atob extraction + XOR unmasking + Function execution constitutes definitive payload execution.',
        sampleMatch: '<img src="data:image/png;base64,... onerror="setTimeout(()=>Function(String.fromCharCode(...))) style="display:none">',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent Hidden Image XOR Loader in HTML
status: experimental
description: Detects HTML documents matching the confluence of concealed image tags, base64 payload extraction, and inline XOR decoding
logsource:
  category: web_content
detection:
  selection_img:
    Content|re: '<img[^>]+src=[\'"\`]data:image\\/(?:jpeg|png|webp);base64,[\\w+/=]{60,}[\'"\`]'
  selection_trigger:
    Content|re: '(?:onload|onerror)\\s*=\\s*[\'"\`]'
  selection_xor:
    Content|re: '(?:b\\^k\\[i\\s*%\\s*k\\.length\\]|\\^=)'
  selection_sink:
    Content|re: '(?:Function\\s*\\(\\s*String\\.fromCharCode|TextDecoder\\(\\)\\.decode)'
  condition: selection_img and selection_trigger and selection_xor and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Audit embedded data URIs in image tags. Implement strict Content-Security-Policy (CSP) restricting img-src to trusted origins.',
  },

  'dom-charset-packer': {
    profileId: 'dom-charset-packer',
    profileLabel: 'DOM Charset Index Packer',
    title: 'HTML DOM Charset Harvesting & Index Unpacking Detection',
    category: 'Defense Evasion / Deobfuscation',
    severity: 'HIGH',
    mitreTechnique: 'T1027.002',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads packed as numeric indices referencing characters dynamically harvested from the hosting HTML document DOM and executed via indirect eval.',
    detectionStrategy:
      'Evaluated against HTML documents. While standard web applications frequently query document.all or document.getElementsByTagName for benign DOM manipulation, the confluence of DOM character set harvesting, base-93 index arithmetic (k=k*93+), packed index string declarations, and dynamic execution sinks offsets false positive risk and exposes the unpacker mechanism.',
    yaraRule: {
      ruleName: 'Exploit_HTML_DOM_Charset_Unpacker',
      description: 'Detects HTML documents with DOM character harvesting and dynamic execution sink in a single confluent term',
      code: `rule Exploit_HTML_DOM_Charset_Unpacker
{
    strings:
        $=/<script[^>]*>(?:[^<]*(?:<[^\\/]))*(?:[^<d]*d)+ocument\\.all\\|\\|document\\.getElementsByTagName\\(['"]\\*['"]\\)(?:(?:[^<]*(?:<[^\\/]))*(?:[^<e]*e)+val|(?:[^<]*(?:<[^\\/]))*(?:[^<s]*s)+et(?:Timeout|Interval)|(?:[^<]*(?:<[^\\/]))*(?:[^<F]*F)+unction)/

    condition:
        all of them and
        filesize < 25MB
}`,
    },
    regexDetections: [
      {
        id: 'char-packer-carrier-term',
        name: 'HTML Host Script Carrier Term',
        role: 'CARRIER_TERM',
        pattern: `<script[^>]*>[\\s\\S]*?(?:document\\.all|getElementsByTagName)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; matches the HTML script container hosting the DOM character harvester.',
        sampleMatch: '<script>(function(){...document.all...})()</script>',
      },
      {
        id: 'char-packer-dom-harvest',
        name: 'DOM Character Harvesting Term',
        role: 'DECODE_TERM',
        pattern: `document\\.all\\s*\\|\\|\\s*document\\.getElementsByTagName\\s*\\(\\s*['"\`]\\*['"\`]\\s*\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static document.all; identifies bulk harvesting of all DOM elements to construct the character reconstruction table.',
        sampleMatch: "document.all||document.getElementsByTagName('*')",
      },
      {
        id: 'char-packer-cargo-string',
        name: 'Packed Base-93 Index Cargo String Term',
        role: 'CARGO_TERM',
        pattern: `\\bP\\s*=\\s*['"\`].{30,}?['"\`]\\s*,\\s*W\\s*=`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static P= and W=; matches the high-entropy index cargo string holding packed character positions. Hyperscan compliant without lookarounds.',
        sampleMatch: 'P="0#\\"\'F-3;G;2($;>)...",W=2',
      },
      {
        id: 'char-packer-math-term',
        name: 'Base-93 Arithmetic Decoding Term',
        role: 'DECODE_TERM',
        pattern: `k=k\\*93\\+`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static k=k*93+; detects the radix-93 polynomial arithmetic formula reconstructing character indices.',
        sampleMatch: 'k=k*93+D[P[i++]]',
      },
      {
        id: 'char-packer-sink-term',
        name: 'Indirect Global Eval Execution Sink Term',
        role: 'SINK_TERM',
        pattern: `\\(0\\s*,\\s*eval\\s*\\)\\(\\w+\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static (0,eval); identifies indirect eval call executing reconstituted payload in global scope.',
        sampleMatch: '(0,eval)(o)',
      },
      {
        id: 'char-packer-compound-rule',
        name: 'Confluent Single-Term End-to-End Rule',
        role: 'CONFLUENT_SUM',
        pattern: `<script[^>]*>(?:[^<]*(?:<[^\\/]))*(?:[^<d]*d)+ocument\\.all\\|\\|document\\.getElementsByTagName\\(['"]\\*['"]\\)(?:(?:[^<]*(?:<[^\\/]))*(?:[^<e]*e)+val|(?:[^<]*(?:<[^\\/]))*(?:[^<s]*s)+et(?:Timeout|Interval)|(?:[^<]*(?:<[^\\/]))*(?:[^<F]*F)+unction)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; matches the confluent carrier-to-sink chain within an unclosed script block connecting DOM character harvesting directly to execution sinks.',
        sampleMatch: '<script>(function(){...document.all||document.getElementsByTagName(\'*\')...(0,eval)(o)...})()</script>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent HTML Charset Index Unpacker in Web Content
status: experimental
description: Detects HTML documents matching the confluence of DOM element scraping, base-93 arithmetic, and indirect eval execution
logsource:
  category: web_content
detection:
  selection_carrier:
    Content|contains: '<script'
  selection_dom:
    Content|re: 'document\\.all\\|\\|document\\.getElementsByTagName\\([\'"\`]\*[\'"\`]\\)'
  selection_arithmetic:
    Content|contains: 'k=k*93+'
  selection_sink:
    Content|contains: '(0,eval)('
  condition: selection_carrier and selection_dom and selection_arithmetic and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Disable inline scripts using Content-Security-Policy (CSP) headers without unsafe-eval. Monitor DOM harvesting loops.',
  },

  'canvas-lsb-steganography': {
    profileId: 'canvas-lsb-steganography',
    profileLabel: 'Canvas LSB Steganography',
    title: 'Canvas LSB Steganography Payload Extraction Detection',
    category: 'Defense Evasion / Stenographic Obfuscation',
    severity: 'HIGH',
    mitreTechnique: 'T1027.003',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads embedded in the least significant bits of image pixel channels, extracted via HTML5 Canvas 2D contexts, bit-shifted, and executed in memory.',
    detectionStrategy:
      'Evaluated against HTML documents. While legitimate web applications use Canvas 2D contexts and getImageData for filters or image analysis, the confluence of carrier image tags with inline onload canvas creation and dynamic execution sinks offsets false positive risk and exposes steganographic delivery in a single confluent term.',
    yaraRule: {
      ruleName: 'Exploit_Canvas_LSB_Stego',
      description: 'Detects HTML carrier image tags with inline onload canvas creation and dynamic execution sinks in a single confluent term',
      code: `rule Exploit_Canvas_LSB_Stego
{
    strings:
        $=/<img\\b(?:[^\\/]*\\/[^>])*(?:[^\\x20\\/]*\\x20)+onload=(?:[^<]*(?:<[^\\/]))*(?:[^<d]*d)+ocument\\.createElement\\(['"\`]canvas['"\`]\\)(?:(?:[^<]*(?:<[^\\/]))*(?:[^<e]*e)+val|(?:[^<]*(?:<[^\\/]))*(?:[^<s]*s)+et(?:Timeout|Interval)|(?:[^<]*(?:<[^\\/]))*(?:[^<F]*F)+unction)/

    condition:
        all of them and
        filesize < 25MB
}`,
    },
    regexDetections: [
      {
        id: 'lsb-stego-carrier-term',
        name: 'Dynamic Canvas Element Allocation Term',
        role: 'CARRIER_TERM',
        pattern: `document\\.createElement\\s*\\(\\s*['"\`]canvas['"\`]\\s*\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static document.createElement; detects programmatic creation of in-memory canvas elements for pixel manipulation.',
        sampleMatch: 'document.createElement("canvas")',
      },
      {
        id: 'lsb-stego-harvest-term',
        name: 'Canvas ImageData Pixel Buffer Harvesting Term',
        role: 'DECODE_TERM',
        pattern: `getImageData\\s*\\([^)]*\\)\\.data`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static getImageData; matches extraction of raw RGBA pixel arrays from the 2D rendering context.',
        sampleMatch: 'x.getImageData(0,0,W,H).data',
      },
      {
        id: 'lsb-stego-decode-term',
        name: 'LSB Bit Accumulation Arithmetic Term',
        role: 'DECODE_TERM',
        pattern: `b\\s*=\\s*b\\s*\\*\\s*2\\s*\\+\\s*\\(?[$\\w]+\\[[^]]+\\]\\s*&\\s*1\\)?|b=b\\*2\\+`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static b=b*2+; matches the bit-shifting accumulator formula shifting previous bits left and adding the pixel LSB.',
        sampleMatch: 'b=b*2+d[p+k]%2',
      },
      {
        id: 'lsb-stego-sink-term',
        name: 'LSB Stego Dynamic Execution Sink Term',
        role: 'SINK_TERM',
        pattern: `b=b\\*2\\+[^;]+;[\\s\\S]{0,100}?(?:\\(\\s*0\\s*,\\s*eval\\s*\\)|eval|setTimeout|setInterval|Function|new\\s+Function)\\s*\\(`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static b=b*2+; verifies that accumulated byte values terminate in an execution sink.',
        sampleMatch: 'b=b*2+d[p+k]%2;if(++n>7){if(!b){(0,eval)(new TextDecoder().decode(...))}}',
      },
      {
        id: 'lsb-stego-compound-rule',
        name: 'Confluent Single-Term End-to-End Rule',
        role: 'CONFLUENT_SUM',
        pattern: `<img\\b(?:[^\\/]*\\/[^>])*(?:[^\\x20\\/]*\\x20)+onload=(?:[^<]*(?:<[^\\/]))*(?:[^<d]*d)+ocument\\.createElement\\(['"\`]canvas['"\`]\\)(?:(?:[^<]*(?:<[^\\/]))*(?:[^<e]*e)+val|(?:[^<]*(?:<[^\\/]))*(?:[^<s]*s)+et(?:Timeout|Interval)|(?:[^<]*(?:<[^\\/]))*(?:[^<F]*F)+unction)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <img; matches HTML carrier image with inline onload canvas allocation and dynamic execution sinks in a single confluent term.',
        sampleMatch: '<img src="data:image/png;base64,..." onload="...document.createElement(\'canvas\')...(0,eval)...">',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent Canvas LSB Steganography Extraction in HTML
status: experimental
description: Detects HTML documents matching the confluence of canvas pixel harvesting, LSB accumulation, and dynamic execution
logsource:
  category: web_content
detection:
  selection_canvas:
    Content|contains: 'createElement("canvas")'
  selection_pixel:
    Content|contains: 'getImageData('
  selection_lsb:
    Content|re: 'b\\s*=\\s*b\\s*\\*\\s*2\\s*\\+'
  selection_sink:
    Content|re: '(?:eval\\(|setTimeout\\(|Function\\()'
  condition: selection_canvas and selection_pixel and selection_lsb and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Sanitize user-uploaded images and re-encode to lossy formats to strip LSB artifacts. Enforce CSP headers forbidding dynamic eval.',
  },

  'property-access-obfuscator': {
    profileId: 'property-access-obfuscator',
    profileLabel: 'Property Access Obfuscation',
    title: 'Property Access Bracket Obfuscation & Hex String Decomposition Detection',
    category: 'Defense Evasion / API Concealment',
    severity: 'MEDIUM',
    mitreTechnique: 'T1027',
    mitreTactics: ['Defense Evasion'],
    summary:
      'Detects JavaScript payloads concealing sensitive DOM method calls (getElementById, createElement) behind bracket notation with hex-escaped string indices or string concatenation.',
    detectionStrategy:
      'Evaluated against HTML documents. While modern JavaScript frameworks occasionally use bracket notation for dynamic key access, the confluence of HTML script containers, bracket-accessed global roots (document/window), hex escape sequences, and concatenated identifiers offsets false positive risk and unmasks API concealing layers.',
    yaraRule: {
      ruleName: 'property_access_obfuscation',
      description: 'Detects HTML documents with Property Obfuscation bracket rewrites and hex escapes',
      code: `rule property_access_obfuscation
{
    strings:
        $=/\\[['"\`]\\w+['"\`](?:\\s*\\+\\s*['"\`]\\w+['"\`])+\\]/
        $=/\\[['"\`]\\w+['"\`]\\]\\(/
        $=/\\[['"\`](?:\\\\x[4567][a-f\\d])+['"\`]\\]/i
        $=/\\[\\({3}\\)=>\\{[^\\}\\n]*\\}\\)\\(\\)\\)\\]\\(/
        $=/\\[String\\.fromCharCode\\((?:\\d{1,3},)+\\d{1,3}\\)\\]\\(/

    condition:
        filesize < 1000000 and
        3 of them
}`,
    },
    regexDetections: [
      {
        id: 'camo-carrier-term',
        name: 'HTML Host Script Carrier Term',
        role: 'CARRIER_TERM',
        pattern: `<script[^>]*>[^<]*?(?:document\\[|window\\[|String\\[|\\\\x[\\da-fA-F]{2})`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; matches script containers holding bracket notation lookups. Benign in isolation on legacy scripts.',
        sampleMatch: '<script>document["\\x67\\x65\\x74\\x45\\x6c\\x65\\x6d\\x65\\x6e\\x74\\x42\\x79\\x49\\x64"]("main")...</script>',
      },
      {
        id: 'camo-hex-property-access',
        name: 'Hex-Escaped Property Access Index Term',
        role: 'DECODE_TERM',
        pattern: `\\[\\s*['"\`]\\\\x[\\da-fA-F]{2}`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static opening bracket ([); matches bracketed properties beginning with hexadecimal byte escapes.',
        sampleMatch: '["\\x67\\x65\\x74\\x45\\x6c\\x65\\x6d\\x65\\x6e\\x74\\x42\\x79\\x49\\x64"]',
      },
      {
        id: 'camo-concat-property-access',
        name: 'String-Concatenated Property Access Term',
        role: 'DECODE_TERM',
        pattern: `(?:document|window)\\[\\s*['"\`][$\\w]+['"\`]\\s*\\+\\s*['"\`][$\\w]+['"\`]\\s*\\]`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static document[ or window[; matches split string literals joined by plus operators to evade static substring searches.',
        sampleMatch: 'document["getElem" + "entById"]',
      },
      {
        id: 'camo-charcode-property-access',
        name: 'FromCharCode Property Access Term',
        role: 'DECODE_TERM',
        pattern: `\\[\\s*(?:String\\b[\\s\\S]{1,60}?\\(\\s*\\d+(?:,\\s*\\d+){2,}\\s*\\)|\\\\x[\\da-fA-F]{2})`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static opening bracket ([); matches multi-character char code sequences or hex escapes accessing object properties to conceal API names.',
        sampleMatch: 'document[String.fromCharCode(103,101,116,69,108,101,109,101,110,116,66,121,73,100)]',
      },
      {
        id: 'camo-compound-rule',
        name: 'Confluent End-to-End Compound Rule (Sum of Terms)',
        role: 'CONFLUENT_SUM',
        pattern: `<script[^>]*>[\\s\\S]*?(?:document|window)\\[\\s*(?:['"\`]\\\\x|['"\`][$\\w]+['"\`]\\s*\\+|String\\[?['"\`]fromCharCode)[\\s\\S]*?<\\/script>`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; the sum of script container + bracket notation + hex escapes/concatenation inside property lookups uniquely identifies the TTP.',
        sampleMatch: '<script>...document["getElem" + "entById"]("status-card")...</script>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent Property Access Obfuscation in HTML
status: experimental
description: Detects HTML documents matching the confluence of script carrier, hex-escaped properties, and concatenated identifier lookups
logsource:
  category: web_content
detection:
  selection_carrier:
    Content|contains: '<script'
  selection_hex:
    Content|re: '\\[\\s*[\'"\`]\\\\x[\\da-fA-F]{2}'
  selection_concat:
    Content|re: '(?:document|window)\\[\\s*[\'"\`][\\w$]+[\'"\`]\\s*\\+\\s*[\'"\`][\\w$]+[\'"\`]\\s*\\]'
  condition: selection_carrier and (selection_hex or selection_concat)`,
      },
    ],
    mitigationAdvice:
      'Audit scripts for dynamic string decomposition and property obfuscation. Enforce Content-Security-Policy script hashing.',
  },

  'url-coordinate-matrix': {
    profileId: 'url-coordinate-matrix',
    profileLabel: 'URL Coordinate Matrix',
    title: 'Node.js Documentation URL Matrix Obfuscation Detection',
    category: 'Defense Evasion / String Character Mapping',
    severity: 'HIGH',
    mitreTechnique: 'T1027',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects JavaScript payloads decomposed into character coordinates mapped onto URL strings and reconstituted in memory via dynamic execution sinks (eval, setTimeout, Function).',
    detectionStrategy:
      'Evaluated against HTML documents. While individual terms (like <script> containers, documentation URLs, charCodeAt calls, or Function constructors) appear in benign web pages, the confluence of HTML script carrier tags, URL reference coordinate lookups, and dynamic execution sinks offsets false positive risk and exposes the underlying payload reconstruction logic.',
    yaraRule: {
      ruleName: 'url_coordinate_matrix_obfuscation',
      description: 'Detects HTML documents combining URL matrix datasets, coordinate unpacking, and dynamic execution sinks',
      code: `rule url_coordinate_matrix_obfuscation
{
    strings:
        $decode_char_code_at=/charCodeAt\\b/
        $decode_from_code_point=/String\\.fromCodePoint\\(parseInt\\(/

        $matrix_url_var_long=/var\\x20[$\\w]+=\\[(?:(?:'[^']{20,}'|"[^"]{20,}"|\`[^\`]{20,}\`),){15}/
        $matrix_url_const_long=/const\\x20[$\\w]+=\\[(?:(?:'[^']{20,}'|"[^"]{20,}"|\`[^\`]{20,}\`),){15}/
        $matrix_url_let_long=/let\\x20[$\\w]+=\\[(?:(?:'[^']{20,}'|"[^"]{20,}"|\`[^\`]{20,}\`),){15}/
        $matrix_url_var_dense=/var\\x20[$\\w]+=\\[(?:(?:'[^']{10,}'|"[^"]{10,}"|\`[^\`]{10,}\`),){30}/
        $matrix_url_const_dense=/const\\x20[$\\w]+=\\[(?:(?:'[^']{10,}'|"[^"]{10,}"|\`[^\`]{10,}\`),){30}/
        $matrix_url_let_dense=/let\\x20[$\\w]+=\\[(?:(?:'[^']{10,}'|"[^"]{10,}"|\`[^\`]{10,}\`),){30}/

        $sink_eval=/eval\\b/
        $sink_set_timeout=/setTimeout\\b/
        $sink_set_interval=/setInterval\\b/
        $sink_function_constructor=/Function\\b/i

    condition:
        filesize < 1000000 and
        all of ($decode_*) and
        any of ($matrix_url_*) and
        any of ($sink_*)
}`,
    },
    regexDetections: [
      {
        id: 'url-matrix-carrier-term',
        name: 'HTML Host Script Carrier Term',
        role: 'CARRIER_TERM',
        pattern: `<script[^>]*>[^<]*?(?:https?:\\/\\/nodejs\\.org|const\\s+_d|\\[\\s*['"\`]https?:\\/\\/)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; matches the HTML script envelope containing URL matrix reference datasets. Benign in isolation on sites referencing documentation.',
        sampleMatch: '<script>const _d=["https://nodejs.org/api/crypto.html",...]',
      },
      {
        id: 'url-matrix-dataset-term',
        name: 'Documentation URL Reference Array Term',
        role: 'CARGO_TERM',
        pattern: `\\[\\s*['"\`]https?:\\/\\/[^'"\`]+\\.html['"\`]`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static opening bracket ([); matches arrays of external documentation URLs acting as character coordinate reference matrices.',
        sampleMatch: '["https://nodejs.org/api/crypto.html","https://nodejs.org/api/fs.html"]',
      },
      {
        id: 'url-matrix-coordinate-cargo',
        name: 'Coordinate Map Base64 Cargo Term',
        role: 'CARGO_TERM',
        pattern: `_f\\s*=\\s*atob\\s*\\(\\s*[$\\w]+\\s*\\)|const\\s+_b\\s*=\\s*['"\`][\\w+/=]{40,}['"\`]`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static _f=atob or const _b=; matches the high-entropy coordinate string decoded into byte offsets.',
        sampleMatch: 'const _b="AAAAFAAAABkAAAA..."',
      },
      {
        id: 'url-matrix-decode-term',
        name: 'Multi-Dimensional CharCode Dereference Term',
        role: 'DECODE_TERM',
        pattern: `charCodeAt\\([^)]*\\)\\]\\[[$\\w]+\\.charCodeAt`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static charCodeAt; matches chained coordinate lookups extracting characters from the URL string array.',
        sampleMatch: '_d[_f.charCodeAt(i)][_f.charCodeAt(i+1)]',
      },
      {
        id: 'url-matrix-sink-term',
        name: 'Dynamic Function Constructor Sink Term',
        role: 'SINK_TERM',
        pattern: `new\\s+Function\\([$\\w]+\\)\\(\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static new Function; detects immediate execution of the reassembled string payload.',
        sampleMatch: 'new Function(p)()',
      },
      {
        id: 'url-matrix-compound-rule',
        name: 'Confluent End-to-End Compound Rule (Sum of Terms)',
        role: 'CONFLUENT_SUM',
        pattern: `<script[^>]*>[\\s\\S]*?\\[\\s*['"\`]https?:\\/\\/[^'"\`]+\\.html['"\`][\\s\\S]*?charCodeAt[\\s\\S]*?(?:new\\s+Function|\\(\\s*0\\s*,\\s*eval\\s*\\)|eval|setTimeout)\\s*\\(`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; the sum of script container + URL array + charCodeAt lookup + dynamic function execution provides 100% confidence with zero benign false positives.',
        sampleMatch: '<script>...const _d=["https://nodejs.org..."]..._d[...].charCodeAt...new Function(p)()...</script>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent URL Matrix Deobfuscator in HTML
status: experimental
description: Detects HTML documents matching the confluence of documentation URL arrays, coordinate dereferencing, and dynamic code evaluation
logsource:
  category: web_content
detection:
  selection_carrier:
    Content|contains: '<script'
  selection_urls:
    Content|re: '\\[\\s*["\x27\x60]https?:\\/\\/[^"\x27\x60]+\\.html["\x27\x60]'
  selection_decode:
    Content|contains: 'charCodeAt('
  selection_sink:
    Content|re: '(?:new\\s+Function\\(|eval\\(|setTimeout\\()'
  condition: selection_carrier and selection_urls and selection_decode and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Inspect scripts referencing external documentation URL lists for character steganography. Restrict dynamic execution using strict CSP.',
  },

  'image-zip-polyglot': {
    profileId: 'image-zip-polyglot',
    profileLabel: 'Polyglot Image ZIP Trailer',
    title: 'Polyglot Image ZIP Trailer Extraction Detection',
    category: 'Defense Evasion / Polyglot Files',
    severity: 'HIGH',
    mitreTechnique: 'T1027.003',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects polyglot image files with appended ZIP archives extracted via client-side DataView byte scanning, inflated, and executed via dynamic sinks.',
    detectionStrategy:
      'Evaluated against HTML documents. While binary DataView scanners are occasionally used in web client image decoders, the confluence of HTML script carriers, DataView binary parsing, PK ZIP magic header markers (80/75 or 0x04034b50), and dynamic execution sinks offsets false positive risk and exposes archive extraction.',
    yaraRule: {
      ruleName: 'image_zip_polyglot_payload',
      description: 'Detects HTML documents extracting and executing polyglot image ZIP archives',
      code: `rule image_zip_polyglot_payload
{
    strings:
        $decode_atob_split=/atob\\(\\w+\\.split\\(['"\`],['"\`]\\)\\[1\\]\\)/
        $decode_data_image=/data:image\\/[\\w!#$%&'*+.^\`|~-]+;base64,/
        $decode_dataview=/DataView\\b/

        $zip_header_align0=/UEs(?:BA|DB)/
        $zip_header_align1=/BLA[Qw]/
        $zip_header_align2=/QSw(?:EC|ME)/

        $sink_eval=/eval\\b/
        $sink_set_timeout=/setTimeout\\b/
        $sink_set_interval=/setInterval\\b/
        $sink_function_constructor=/Function\\b/i

    condition:
        filesize < 1000000 and
        all of ($decode_*) and
        any of ($zip_header_*) and
        any of ($sink_*)
}`,
    },
    regexDetections: [
      {
        id: 'zip-appender-carrier-term',
        name: 'DataView Binary Stream Scanner Term',
        role: 'CARRIER_TERM',
        pattern: `new\\s+DataView\\s*\\([^)]+\\)[\\s\\S]{0,120}?IEND`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static new DataView; detects binary scanner seeking PNG IEND chunk boundaries. Benign in isolation on PNG chunk decoders.',
        sampleMatch: 'const v=new DataView(b.buffer...);while(...){if(t=="IEND")return o;}',
      },
      {
        id: 'zip-appender-decode-term',
        name: 'PK Zip Header Byte Signature Term',
        role: 'DECODE_TERM',
        pattern: `\\[[$\\w]+\\]===80&&[$\\w]+\\[[$\\w]+\\+1\\]===75`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static ===80; matches binary comparisons scanning for PK zip magic bytes (80, 75).',
        sampleMatch: 'if(z[p]===80&&z[p+1]===75&&z[p+2]===3&&z[p+3]===4)',
      },
      {
        id: 'zip-appender-sink-term',
        name: 'TextDecoder Dynamic Execution Sink Term',
        role: 'SINK_TERM',
        pattern: `TextDecoder\\s*\\(\\s*\\)\\.decode\\s*\\([$\\w]+\\.subarray[\\s\\S]{0,50}?(?:\\(\\s*0\\s*,\\s*eval\\s*\\)|eval|setTimeout|setInterval|Function)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static TextDecoder; verifies that unzipped binary slices pass into dynamic execution sinks.',
        sampleMatch: 'var payload=new TextDecoder().decode(z.subarray(st,st+cs));(0,eval)(payload);',
      },
      {
        id: 'zip-appender-compound-rule',
        name: 'Confluent End-to-End Compound Rule (Sum of Terms)',
        role: 'CONFLUENT_SUM',
        pattern: `<script[^>]*>[\\s\\S]*?DataView[\\s\\S]*?(?:80\\s*&&|0x04034b50)[\\s\\S]*?TextDecoder[\\s\\S]*?(?:\\(\\s*0\\s*,\\s*eval\\s*\\)|eval|setTimeout)\\s*\\(`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on static <script; the sum of DataView scanning + PK zip signature checking + TextDecoder eval constitutes definitive extraction.',
        sampleMatch: '<script>...DataView...80&&75...TextDecoder...(0,eval)...</script>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent Polyglot Image ZIP Extraction in HTML
status: experimental
description: Detects HTML documents matching the confluence of DataView parsing, PK zip magic bytes, and dynamic evaluation
logsource:
  category: web_content
detection:
  selection_carrier:
    Content|contains: '<script'
  selection_scanner:
    Content|contains: 'DataView('
  selection_pk:
    Content|re: '(?:===80&&|0x04034b50)'
  selection_sink:
    Content|re: '(?:eval\\(|setTimeout\\(|Function\\()'
  condition: selection_carrier and selection_scanner and selection_pk and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Strip trailing data after PNG IEND markers or JPEG EOI markers on web proxies. Prevent inline script execution with CSP.',
  },

  'image-zip-cdn-polyglot': {
    profileId: 'image-zip-cdn-polyglot',
    profileLabel: 'Polyglot Image ZIP (Cloudflare CDN)',
    title: 'Cloudflare CDN JSZip Polyglot Image Extraction Detection',
    category: 'Defense Evasion / Polyglot & External CDN',
    severity: 'HIGH',
    mitreTechnique: 'T1027.003',
    mitreTactics: ['Defense Evasion', 'Execution'],
    summary:
      'Detects polyglot image files with appended ZIP archives unpacked dynamically via a trailing external Cloudflare cdnjs JSZip script import placed at the end of the document with an inline onload execution hook.',
    detectionStrategy:
      'Evaluated against HTML documents. Identifies the confluence of data URI carrier images and an external cdnjs JSZip script placed at the document boundary / end of file, utilizing an inline onload execution hook calling JSZip.loadAsync and dynamic evaluation sinks (eval).',
    yaraRule: {
      ruleName: 'cloudflare_cdn_jszip_polyglot',
      description: 'Detects HTML documents extracting and executing polyglot image ZIP archives',
      code: `rule cloudflare_cdn_jszip_polyglot
{
    strings:
        $decode_atob_split=/atob\\(\\w+\\.split\\(['"\`],['"\`]\\)\\[1\\]\\)/
        $decode_data_image=/data:image\\/[\\w!#$%&'*+.^\`|~-]+;base64,/
        $decode_dataview=/DataView\\b/

        $zip_header_align0=/UEs(?:BA|DB)/
        $zip_header_align1=/BLA[Qw]/
        $zip_header_align2=/QSw(?:EC|ME)/

        $sink_eval=/eval\\b/
        $sink_set_timeout=/setTimeout\\b/
        $sink_set_interval=/setInterval\\b/
        $sink_function_constructor=/Function\\b/i

    condition:
        filesize < 1000000 and
        all of ($decode_*) and
        any of ($zip_header_*) and
        any of ($sink_*)
}`,
    },
    regexDetections: [
      {
        id: 'zip-cdn-script-import',
        name: 'Cloudflare cdnjs JSZip Import Tag Term',
        role: 'CARRIER_TERM',
        pattern: `<script\\s+[^>]*src=['"][^'"]*cdnjs\\.cloudflare\\.com\\/ajax\\/libs\\/jszip\\/[^'"]*jszip\\.min\\.js['"]`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on cdnjs.cloudflare.com; matches the external script tag loading the JSZip library.',
        sampleMatch: '<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js" onload="...">',
      },
      {
        id: 'zip-cdn-onload-hook',
        name: 'Inline Onload Extraction Handler Term',
        role: 'DECODE_TERM',
        pattern: `onload=['"][^'"]*JSZip\\.loadAsync`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored on onload; identifies inline event handler calling JSZip.loadAsync to unpack the polyglot trailer.',
        sampleMatch: `onload='(async()=>{...const z=await JSZip.loadAsync(b.slice(F(b)))...})()'`,
      },
      {
        id: 'zip-cdn-sink-term',
        name: 'JSZip Dynamic Execution Sink Term',
        role: 'SINK_TERM',
        pattern: `(?:\\(\\s*0\\s*,\\s*eval\\s*\\)|eval)\\s*\\(\\s*(?:await\\s+)?[^)]*\\)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Verifies extracted text contents from the archive pass directly into dynamic execution sinks (eval).',
        sampleMatch: 'eval(await Object.values(z.files)[0].async("string"));',
      },
      {
        id: 'zip-cdn-eof-placement',
        name: 'Trailing Document Placement Term',
        role: 'CARRIER_TERM',
        pattern: `<script\\s+[^>]*src=['"][^'"]*cdnjs\\.cloudflare\\.com\\/ajax\\/libs\\/jszip[\\s\\S]*?<\\/script>\\s*(?:<\\/(?:body|html)>|$)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Anchored at document boundary; matches the Cloudflare JSZip unpacker script placed at the end of the file preceding </body>, </html>, or EOF to ensure post-carrier DOM resolution.',
        sampleMatch: '<script src="https://cdnjs.cloudflare.com/.../jszip.min.js" onload="..."></script></body>',
      },
      {
        id: 'zip-cdn-compound-rule',
        name: 'Confluent End-to-End Cloudflare JSZip Polyglot Rule',
        role: 'CONFLUENT_SUM',
        pattern: `<script\\s+[^>]*src=['"][^'"]*cdnjs\\.cloudflare\\.com\\/ajax\\/libs\\/jszip[\\s\\S]*?onload=['"][\\s\\S]*?JSZip\\.loadAsync[\\s\\S]*?(?:\\(\\s*0\\s*,\\s*eval\\s*\\)|eval)`,
        flags: 'gmi',
        flavor: 'ECMAScript',
        description: 'Sum of Cloudflare JSZip script tag + onload hook + loadAsync + eval execution represents 100% true positive polyglot execution.',
        sampleMatch: '<script src="https://cdnjs.cloudflare.com/.../jszip.min.js" onload="...JSZip.loadAsync...eval(...)"></script>',
      },
    ],
    siemDetections: [
      {
        platform: 'Sigma',
        query: `title: Confluent Cloudflare CDN JSZip Image Polyglot Unpacker at End of HTML Document
status: experimental
description: Detects HTML documents appending an external Cloudflare CDN JSZip unpacker script at the end of the file following carrier image markup
logsource:
  category: web_content
detection:
  selection_cdn:
    Content|contains: 'cdnjs.cloudflare.com/ajax/libs/jszip'
  selection_onload:
    Content|contains: 'onload='
  selection_jszip:
    Content|contains: 'JSZip.loadAsync'
  selection_sink:
    Content|re: '(?:\\(0,eval\\)|eval\\()'
  selection_eof:
    Content|re: 'cdnjs\\.cloudflare\\.com\\/ajax\\/libs\\/jszip[\\s\\S]*?<\\/script>\\s*(?:<\\/(?:body|html)>)?'
  condition: selection_cdn and selection_onload and selection_jszip and selection_sink`,
      },
    ],
    mitigationAdvice:
      'Enforce strict Content-Security-Policy (CSP) headers restricting script-src to self or trusted origins with nonces, and disallow inline script event attributes (unsafe-inline). Strip trailing payload bytes following PNG IEND / JPEG EOI markers at web inspection gateways.',
  },
};

// Transparent backward compatibility aliases for legacy engine IDs
PROFILE_DETECTION_SPECS['element-hook'] = PROFILE_DETECTION_SPECS['dom-method-hook'];
PROFILE_DETECTION_SPECS['hidden-img-xor'] = PROFILE_DETECTION_SPECS['image-onerror-xor'];
PROFILE_DETECTION_SPECS['html-char-packer'] = PROFILE_DETECTION_SPECS['dom-charset-packer'];
PROFILE_DETECTION_SPECS['lsb-stego'] = PROFILE_DETECTION_SPECS['canvas-lsb-steganography'];
PROFILE_DETECTION_SPECS['code-camo'] = PROFILE_DETECTION_SPECS['property-access-obfuscator'];
PROFILE_DETECTION_SPECS['codecamo'] = PROFILE_DETECTION_SPECS['property-access-obfuscator'];
PROFILE_DETECTION_SPECS['url-matrix'] = PROFILE_DETECTION_SPECS['url-coordinate-matrix'];
PROFILE_DETECTION_SPECS['zip-appender'] = PROFILE_DETECTION_SPECS['image-zip-polyglot'];
