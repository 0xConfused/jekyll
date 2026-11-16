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
      'Detects repeated common browser/DOM function names, rebinding, ===[1-9], map/forEach, try block, and dynamic execution sinks (eval, setTimeout, setInterval, Function).',
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
  },
  'image-onerror-xor': {
    profileId: 'image-onerror-xor',
    profileLabel: 'Image Onerror XOR Carrier',
    title: 'Concealed Image XOR Payload Extraction Detection',
    summary:
      'Detects JavaScript payloads hidden in base64 data URIs of concealed <img> tags, extracted and unmasked via inline onerror event handlers with XOR operations, and executed dynamically.',
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
  },

  'dom-charset-packer': {
    profileId: 'dom-charset-packer',
    profileLabel: 'DOM Charset Index Packer',
    title: 'HTML DOM Charset Harvesting & Index Unpacking Detection',
    summary:
      'Detects JavaScript payloads packed as numeric indices referencing characters dynamically harvested from the hosting HTML document DOM and executed via indirect eval.',
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
  },

  'canvas-lsb-steganography': {
    profileId: 'canvas-lsb-steganography',
    profileLabel: 'Canvas LSB Steganography',
    title: 'Canvas LSB Steganography Payload Extraction Detection',
    summary:
      'Detects JavaScript payloads embedded in the least significant bits of image pixel channels, extracted via HTML5 Canvas 2D contexts, bit-shifted, and executed in memory.',
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
  },

  'property-access-obfuscator': {
    profileId: 'property-access-obfuscator',
    profileLabel: 'Property Access Obfuscation',
    title: 'Property Access Bracket Obfuscation & Hex String Decomposition Detection',
    summary:
      'Detects JavaScript payloads concealing sensitive DOM method calls (getElementById, createElement) behind bracket notation with hex-escaped string indices or string concatenation.',
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
  },

  'url-coordinate-matrix': {
    profileId: 'url-coordinate-matrix',
    profileLabel: 'URL Coordinate Matrix',
    title: 'Node.js Documentation URL Matrix Obfuscation Detection',
    summary:
      'Detects JavaScript payloads decomposed into character coordinates mapped onto URL strings and reconstituted in memory via dynamic execution sinks (eval, setTimeout, Function).',
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
  },

  'image-zip-polyglot': {
    profileId: 'image-zip-polyglot',
    profileLabel: 'Polyglot Image ZIP Trailer',
    title: 'Polyglot Image ZIP Trailer Extraction Detection',
    summary:
      'Detects polyglot image files with appended ZIP archives extracted via client-side DataView byte scanning, inflated, and executed via dynamic sinks.',
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
  },

  'image-zip-cdn-polyglot': {
    profileId: 'image-zip-cdn-polyglot',
    profileLabel: 'Polyglot Image ZIP (Cloudflare CDN)',
    title: 'Cloudflare CDN JSZip Polyglot Image Extraction Detection',
    summary:
      'Detects polyglot image files with appended ZIP archives unpacked dynamically via a trailing external Cloudflare cdnjs JSZip script import placed at the end of the document with an inline onload execution hook.',
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
