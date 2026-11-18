"""Threat signatures for the rule-based shield.

Patterns are grouped by attack type. `fold()` produces the text variants they run on, so
simple obfuscation (leetspeak, dotted or hyphenated letters) does not hide an attack.
Multilingual signatures run on the un-folded text, because folding would corrupt
non-Latin scripts.
"""

import re
from typing import Dict, List

_VERBS_LEAK = r"(?:reveal|show|print|repeat|output|display|dump|tell\s+me|give\s+me|share|leak|expose)"
_VERBS_DROP = r"(?:ignore|disregard|forget|override|discard)"
_PRIOR = r"(?:previous|prior|earlier|above|preceding|former|original|system|safety|initial)"
_RULES = r"(?:instructions?|directives?|rules|guidelines|programming|prompt|commands|training)"
# "ignore the previous instructions in the recipe" talks ABOUT a named document's instructions, not the model's.
# The exception only applies when the very next words name a document; "in this conversation" or "for the rest of
# the chat" do NOT excuse an attack, so an attacker cannot buy an exemption by appending a harmless-sounding tail.
_DOC_NOUN = (r"(?:recipe|document|doc|file|e-?mail|article|report|manual|contract|spreadsheet|ticket|form|policy|"
             r"script|essay|paper|page|handbook|guide|assignment|homework|worksheet|template|letter|memo|brief|slides?|deck)")
# Words that turn "about/for/on ..." back into an instruction to the model rather than a topic.
_SELF_REFERENCE = (r"(?:safety|security|restrictions?|ethics|limits|limitations|filters?|guardrails|content|everything|anything|"
                   r"rest|remainder|duration|conversation|chat|session|thread|prompt|message|answers?|responses?)")
_NOT_ABOUT_A_DOCUMENT = (
    r"(?!\s+(?:in|from|within|inside)\s+(?:the\s+|this\s+|that\s+|my\s+|our\s+|an?\s+)?(?:[a-z\-]+\s+){0,2}" + _DOC_NOUN + r"\b"
    r"|\s+(?:on|for|at|about)\s+(?!(?:[a-z']+\s+){0,2}" + _SELF_REFERENCE + r"\b))"
)
# "enable developer mode" is a normal phone/browser setting; excused only when a device or browser is named right after it
_NOT_A_DEVICE = (
    r"(?!(?:\s+(?:on|in|for|of)\s+(?:my|your|the|an?|this|that)\s+|\s+(?:on|in|for|of)\s+)?"
    r"(?:android|iphone|ipad|ios|phone|tablet|browser|chrome|firefox|safari|edge|xbox|steam|windows|samsung|usb|settings)\b)"
)

# English signatures, matched against the folded (lowercase, de-obfuscated) text.
ENGLISH: Dict[str, List[str]] = {
    "direct_injection": [
        r"ignore\s+(?:previous|all)\s+instructions",  # original signature
        rf"\b{_VERBS_DROP}\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your\s+|the\s+|my\s+|these\s+|those\s+)?{_PRIOR}\s+{_RULES}\b{_NOT_ABOUT_A_DOCUMENT}",
        rf"\b{_VERBS_DROP}\s+(?:all|your|any)\s+(?:of\s+)?(?:the\s+)?(?:{_RULES}|restrictions|ethics|safety)",
        r"\bforget\s+(?:everything|all)\s+(?:you\s+(?:were|have\s+been)\s+told|i\s+said|above|before)",
        r"\byou\s+(?:no\s+longer|don'?t|do\s+not)\s+(?:have|need\s+to\s+follow)\s+(?:any\s+)?(?:restrictions|rules|limits|guidelines)",
        rf"\b(?:throw\s+away|set\s+aside|pay\s+no\s+attention\s+to|never\s?mind|cancel(?:led)?)\s+(?:all\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:{_PRIOR}|developer|system)?\s*(?:{_RULES}|orders|directions|messages?|guidelines)",
    ],
    "prompt_leak": [
        r"reveal\s+(?:your\s+)?(?:password|secret|api[_\s]?key)",  # original signature
        rf"{_VERBS_LEAK}\b.{{0,30}}\b(?:your|the)\s+(?:system|initial|original|hidden|secret|internal)\s+(?:prompt|instructions|configuration|config|rules)",
        r"\brepeat\s+(?:everything|all|the\s+text|the\s+words)\s+(?:above|before)\b",
        rf"\b{_VERBS_LEAK}\b.{{0,40}}\b(?:your|admin|root|system|internal|hidden|stored|environment)\b.{{0,40}}\b(?:passwords?|credentials|api[_\s]?keys?|secret\s+keys?|private\s+keys?|access\s+tokens?)\b",
        r"\b(?:paste|quote|print|output|read\s+back|reveal|show|repeat|display)\b.{0,40}\b(?:your|their|its)\s+(?:full\s+|exact\s+|complete\s+)?(?:instructions|prompt|rules|system\s+message)\b",
        r"\b(?:your|their|its)\s+(?:hidden|system|secret|initial)\s+(?:prompt|instructions|message)\b",
    ],
    "jailbreak": [
        r"you\s+are\s+now\s+dan",  # original signature
        rf"enable\s+developer\s+mode{_NOT_A_DEVICE}",  # original signature, minus the phone/browser setting
        r"bypass\s+rules",  # original signature
        r"bypass\s+(?:safety|security)",  # original signature
        r"\byou\s+are\s+(?:now\s+)?dan\b",
        r"\bdo\s+anything\s+now\b",
        rf"\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|evil|dan|jail(?:break(?:ed)?|broken)|unrestricted)\s+mode\b{_NOT_A_DEVICE}",
        r"\bbypass\s+(?:the\s+|all\s+|your\s+)?(?:safety|security|content|rules?|restrictions?|filters?|guardrails?)\b",
        r"\bdisable\s+(?:all\s+|your\s+)?(?:content\s+|safety\s+|security\s+)?(?:filters?|restrictions|safeguards|guardrails)\b",
        r"\b(?:unfiltered|uncensored|unrestricted)\s+(?:ai|model|mode|assistant|version)\b",
        r"\b(?:ai|model|assistant|bot|chatbot)\b.{0,40}\b(?:no|without(?:\s+any)?)\s+(?:restrictions|limits|limitations|filters|safety\s+rules|guardrails|rules)\b(?!\s+(?:on|for|in|of)\b)",
        r"\b(?:act|pretend|roleplay)\b.{0,20}\b(?:as|to\s+be)\b.{0,10}\b(?:deceased|late|dead)\s+(?:grand)?(?:mother|father|ma|pa)\b",
    ],
}

# Key phrases with every non-alphanumeric character removed, so "i.g.n.o.r.e",
# "ignore-previous-instructions" and "i g n o r e" all collapse to the same string.
SQUEEZED = [
    "ignorepreviousinstructions", "ignoreallinstructions", "ignorepriorinstructions",
    "ignoreyourinstructions", "disregardpreviousinstructions", "disregardyourinstructions",
    "forgetpreviousinstructions", "revealyourpassword", "revealyoursystemprompt",
    "bypasssecurityfilters", "bypasssafetyfilters", "youarenowdan",
]

# Multilingual signatures, matched against the un-folded lowercase text.
MULTILINGUAL: Dict[str, List[str]] = {
    "es": [r"ignor[ae]r?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)",
           r"olvida\s+(?:todo\s+lo\s+anterior|tus\s+instrucciones)", r"mu[eé]strame\s+tu\s+(?:contrase[nñ]a|prompt\s+del\s+sistema)"],
    "fr": [r"ignor(?:e|ez|er)\s+(?:toutes\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)",
           r"oubliez?\s+(?:vos|tes)\s+instructions", r"montre(?:z)?[- ]moi\s+(?:ton|votre)\s+mot\s+de\s+passe"],
    "de": [r"ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|fr[uü]heren|bisherigen)\s+(?:anweisungen|instruktionen)",
           r"vergiss\s+(?:alle\s+)?(?:deine|vorherigen)\s+(?:anweisungen|regeln)", r"zeig(?:e)?\s+mir\s+(?:dein|das)\s+passwort"],
    "it": [r"ignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+(?:precedenti|anteriori)", r"dimentica\s+(?:le\s+tue\s+)?istruzioni"],
    "pt": [r"ignore\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores", r"esque[cç]a\s+(?:as\s+)?suas\s+instru[cç][oõ]es"],
    "tr": [r"[öo]nceki\s+(?:t[ae]limatlar[ıi]|y[öo]nergeleri|komutlar[ıi])\w*\s+(?:yok\s+say|g[öo]rmezden\s+gel|unut)"],
    "ru": [r"игнорир\w+\s+(?:все\s+)?(?:предыдущие|прошлые|прежние)\s+(?:инструкции|указания)",
           r"забудь\s+(?:все\s+)?(?:предыдущие|свои)\s+(?:инструкции|указания)"],
    "zh": [r"忽略(?:之前|以前|先前|上面)的?(?:所有)?(?:指令|指示|说明|提示)", r"无视(?:之前|以前|先前)的?(?:所有)?(?:指令|指示|规则)"],
    "ja": [r"(?:以前|前)の(?:指示|命令)を(?:すべて)?無視"],
}

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def fold(text: str) -> List[str]:
    """Return the lowercase text plus its leetspeak-folded variant."""
    lowered = text.lower()
    variants = [lowered]
    leet = lowered.translate(_LEET)
    if leet != lowered:
        variants.append(leet)
    return variants


def squeeze(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.translate(_LEET))


def all_english() -> List[str]:
    return [p for group in ENGLISH.values() for p in group]
