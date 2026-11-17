// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ProfileDetectionSpec {
  profileId: string;
  profileLabel: string;
  title: string;
  summary: string;
  yaraRule: {
    ruleName: string;
    description: string;
    code: string;
  };
}

export const PROFILE_DETECTION_SPECS: Record<string, ProfileDetectionSpec> = {
  'dom-method-hook': {
    profileId: 'dom-method-hook',
    profileLabel: 'DOM Method Hooking',
    title: 'Common DOM Function Rebinding & Execution Hijacking Detection',
    summary:
      'This rule keeps matches inside one <script> tag with [^<]*<[^/] guards and ! <= 500 to prevent cross-script false positives. A repeated DOM API name with =[^=] separates method replacement from normal calls and == comparisons. An arity check (===[1-9] or N in arg?) identifies the switch that passes single-argument calls normally and diverts multi-argument calls. The .map or .forEach call with try { finds the loop that runs each argument and ignores errors from decoy inputs. A dynamic execution sink (eval, setTimeout, setInterval, Function, or => {) confirms code execution instead of normal DOM wrappers.',
    yaraRule: {
      ruleName: 'JS_Common_Function_Rebinding_Map_Execution',
      description:
        'Detects single-script DOM method replacement, multi-argument switching, error-ignoring iteration, and dynamic execution sinks within 500 bytes to prevent false positives.',
      code: `rule JS_Common_Function_Rebinding_Map_Execution
{
    strings:
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateElement\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateElement\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementById\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementById\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelector\\b(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelector\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelectorAll\\b(?:[^<]*<[^\\/])*(?:[^<q]*q)+uerySelectorAll\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateTextNode\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+reateTextNode\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByClassName\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByClassName\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByTagName\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByTagName\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByName\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etElementsByName\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttribute\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttribute\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttribute\\b(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttribute\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<t]*t)+oggleAttribute\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+oggleAttribute\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ddEventListener\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ddEventListener\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveEventListener\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveEventListener\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<d]*d)+ispatchEvent\\b(?:[^<]*<[^\\/])*(?:[^<d]*d)+ispatchEvent\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppendChild\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppendChild\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveChild\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveChild\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertBefore\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertBefore\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChild\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChild\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+loneNode\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+loneNode\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+ontains\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+ontains\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<m]*m)+atches\\b(?:[^<]*<[^\\/])*(?:[^<m]*m)+atches\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+losest\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+losest\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etRootNode\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etRootNode\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+ompareDocumentPosition\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+ompareDocumentPosition\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNode\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNode\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttributeNode\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etAttributeNode\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttributeNode\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emoveAttributeNode\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNames\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etAttributeNames\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttributes\\b(?:[^<]*<[^\\/])*(?:[^<h]*h)+asAttributes\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ttachShadow\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ttachShadow\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentElement\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentElement\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentHTML\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentHTML\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentText\\b(?:[^<]*<[^\\/])*(?:[^<i]*i)+nsertAdjacentText\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<b]*b)+efore\\b(?:[^<]*<[^\\/])*(?:[^<b]*b)+efore\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+fter\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+fter\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceWith\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceWith\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+emove\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+emove\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<p]*p)+repend\\b(?:[^<]*<[^\\/])*(?:[^<p]*p)+repend\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppend\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+ppend\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChildren\\b(?:[^<]*<[^\\/])*(?:[^<r]*r)+eplaceChildren\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<f]*f)+ocus\\b(?:[^<]*<[^\\/])*(?:[^<f]*f)+ocus\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<b]*b)+lur\\b(?:[^<]*<[^\\/])*(?:[^<b]*b)+lur\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<c]*c)+lick\\b(?:[^<]*<[^\\/])*(?:[^<c]*c)+lick\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+croll\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+croll\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollTo\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollTo\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollBy\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollBy\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollIntoView\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+crollIntoView\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etBoundingClientRect\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etBoundingClientRect\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<g]*g)+etClientRects\\b(?:[^<]*<[^\\/])*(?:[^<g]*g)+etClientRects\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<a]*a)+nimate\\b(?:[^<]*<[^\\/])*(?:[^<a]*a)+nimate\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etTimeout\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etTimeout\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i
        $=/<script[^>]*>(?:[^<]*<[^\\/])*(?:[^<s]*s)+etInterval\\b(?:[^<]*<[^\\/])*(?:[^<s]*s)+etInterval\\s*=[^=](?:[^<]*<[^\\/])*(?:(?:[^<=]*=)+==[1-9]|[^<]*\\b[1-9]\\d*\\x20+in\\x20+[$\\w]+\\?)(?:[^<]*<[^\\/])*(?:[^<.]*\\.)+(?:map|forEach)\\b(?:[^<]*<[^\\/])*(?:[^<t]*t)+ry\\s*\\{(?:[^<;]*<[^\\/;])*(?:(?:(?:[^<;e]*e)+val|(?:[^<;s]*s)+et(?:Timeout|Interval)|(?:[^<;F]*F)+unction)\\s*(?:['"\`]\\s*\\]\\s*)?\\(|(?:[^<;)]*\\))+\\s*=>\\s*\\{)/i

    condition:
        for any of them : ($ and ! <= 500)
}`,
    },
  },
  'image-onerror-xor': {
    profileId: 'image-onerror-xor',
    profileLabel: 'Image Onerror XOR Carrier',
    title: 'Concealed Image XOR Payload Extraction Detection',
    summary:
      'The filesize < 25MB limit skips large files to keep scans fast. Matching an <img> tag with id or onerror finds the element that triggers script execution when an image fails to load. Requiring data:image/;base64, inside the same <img> tag separates hidden inline payloads from normal external image URLs. The .src.split(\',\')[1] check confirms that the handler reads base64 data directly from the image source. The XOR operation (^ or ^= with modulo key index) confirms repeating-key decoding instead of normal error logging.',
    yaraRule: {
      ruleName: 'concealed_image_xor_payload',
      description:
        'Detects <img> tags with id or onerror attributes, inline base64 image data, .src.split extraction, and repeating-key XOR decoding under 25 MB.',
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
  },

  'dom-charset-packer': {
    profileId: 'dom-charset-packer',
    profileLabel: 'DOM Charset Index Packer',
    title: 'HTML DOM Charset Harvesting & Index Unpacking Detection',
    summary:
      'The filesize < 25MB limit keeps scans fast by skipping large normal documents. Guards with <script> and [^<]*<[^/] keep the entire match inside one script block to prevent false positives across tags. Matching document.all||document.getElementsByTagName(\'*\') finds the DOM collector that builds a character table from host HTML elements. Requiring a following eval, setTimeout, setInterval, or Function sink confirms that the script runs the decoded characters instead of only reading DOM nodes.',
    yaraRule: {
      ruleName: 'Exploit_HTML_DOM_Charset_Unpacker',
      description:
        'Detects DOM character-table collection and dynamic execution sinks inside one <script> block under 25 MB to prevent cross-tag false positives.',
      code: `rule Exploit_HTML_DOM_Charset_Unpacker
{
    strings:
        $=/<script[^>]*>(?:[^<]*(?:<[^\\/]))*(?:[^<d]*d)+ocument\\.all\\|\\|document\\.getElementsByTagName\\(['"]\\*['"]\\)(?:(?:[^<]*(?:<[^\\/]))*(?:[^<e]*e)+val|(?:[^<]*(?:<[^\\/]))*(?:[^<s]*s)+et(?:Timeout|Interval)|(?:[^<]*(?:<[^\\/]))*(?:[^<F]*F)+unction)/

    condition:
        all of them and
        filesize < 25MB
}`,
    },
  },

  'canvas-lsb-steganography': {
    profileId: 'canvas-lsb-steganography',
    profileLabel: 'Canvas LSB Steganography',
    title: 'Canvas LSB Steganography Payload Extraction Detection',
    summary:
      'The filesize < 25MB limit skips large files so scans stay fast. Matching <img with an inline onload attribute keeps the trigger inside one image tag with [^\\/]*\\/[^>]* guards. Requiring document.createElement(\'canvas\') before any closing tag confirms that the load handler creates a hidden canvas to read image pixel bits. Requiring eval, setTimeout, setInterval, or Function confirms that the handler runs extracted pixel data as code instead of doing normal image processing.',
    yaraRule: {
      ruleName: 'Exploit_Canvas_LSB_Stego',
      description:
        'Detects <img> tags with inline onload canvas creation and dynamic execution sinks within one tag block under 25 MB.',
      code: `rule Exploit_Canvas_LSB_Stego
{
    strings:
        $=/<img\\b(?:[^\\/]*\\/[^>])*(?:[^\\x20\\/]*\\x20)+onload=(?:[^<]*(?:<[^\\/]))*(?:[^<d]*d)+ocument\\.createElement\\(['"\`]canvas['"\`]\\)(?:(?:[^<]*(?:<[^\\/]))*(?:[^<e]*e)+val|(?:[^<]*(?:<[^\\/]))*(?:[^<s]*s)+et(?:Timeout|Interval)|(?:[^<]*(?:<[^\\/]))*(?:[^<F]*F)+unction)/

    condition:
        all of them and
        filesize < 25MB
}`,
    },
  },

  'property-access-obfuscator': {
    profileId: 'property-access-obfuscator',
    profileLabel: 'Property Access Obfuscation',
    title: 'Property Access Bracket Obfuscation & Hex String Decomposition Detection',
    summary:
      'The filesize < 1000000 limit keeps scans fast on files under 1 MB. Requiring 3 of them prevents false positives on normal scripts that use one bracket lookup. Split string keys ([\'a\' + \'b\']) and hex escapes ([\\x...]) find property names hidden from plain text rules. Constant bracket calls like [\'prop\']( find dot calls rewritten as bracket lookups. Closure bracket calls and String.fromCharCode keys find runtime functions that build hidden method names dynamically.',
    yaraRule: {
      ruleName: 'property_access_obfuscation',
      description:
        'Detects files under 1 MB with at least three bracket-call, string-split, hex-escape, or String.fromCharCode obfuscation patterns to limit false positives.',
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
  },

  'url-coordinate-matrix': {
    profileId: 'url-coordinate-matrix',
    profileLabel: 'URL Coordinate Matrix',
    title: 'Node.js Documentation URL Matrix Obfuscation Detection',
    summary:
      'The filesize < 1000000 limit excludes files over 1 MB for fast scanning. Requiring all of ($decode_*) confirms both charCodeAt and String.fromCodePoint(parseInt( calls, which rebuild script text from string coordinates. Requiring any of ($matrix_url_*) finds large var, const, or let arrays used as character lookup tables. The 16-item and 31-item thresholds separate these tables from small normal arrays. Requiring any of ($sink_*) confirms that the script runs the rebuilt string as code.',
    yaraRule: {
      ruleName: 'url_coordinate_matrix_obfuscation',
      description:
        'Detects coordinate decoders, large string-matrix arrays, and dynamic execution sinks together under 1 MB to separate payload loaders from normal arrays.',
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
  },

  'image-zip-polyglot': {
    profileId: 'image-zip-polyglot',
    profileLabel: 'Polyglot Image ZIP Trailer',
    title: 'Polyglot Image ZIP Trailer Extraction Detection',
    summary:
      'The filesize < 1000000 limit keeps scans fast on files under 1 MB. Requiring all of ($decode_*) confirms base64 image splitting with atob and DataView byte scanning to find hidden archive data. Requiring any of ($zip_header_*) checks all three base64 alignments (UEs, BLA, QSw) so shifted ZIP PK headers cannot bypass detection. Requiring any of ($sink_*) confirms that the script runs extracted archive code with eval, setTimeout, setInterval, or Function.',
    yaraRule: {
      ruleName: 'image_zip_polyglot_payload',
      description:
        'Detects inline base64 images scanned with DataView, three-alignment base64 ZIP headers, and dynamic execution sinks under 1 MB.',
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
  },

  'image-zip-cdn-polyglot': {
    profileId: 'image-zip-cdn-polyglot',
    profileLabel: 'Polyglot Image ZIP (Cloudflare CDN)',
    title: 'Cloudflare CDN JSZip Polyglot Image Extraction Detection',
    summary:
      'The filesize < 1000000 limit keeps scans fast on files under 1 MB. Requiring all of ($decode_*) confirms inline base64 image splitting with atob and DataView scanning before an external ZIP library unpacks the trailer. Requiring any of ($zip_header_*) checks all three base64 alignments (UEs, BLA, QSw) so bit-shifted ZIP PK headers still match. Requiring any of ($sink_*) confirms that the onload hook runs extracted archive contents with eval, setTimeout, setInterval, or Function.',
    yaraRule: {
      ruleName: 'cloudflare_cdn_jszip_polyglot',
      description:
        'Detects base64 polyglot images scanned with DataView, three-alignment ZIP headers, and dynamic execution sinks under 1 MB.',
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
