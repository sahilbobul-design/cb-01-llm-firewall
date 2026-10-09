/*
    YARA Rules for Webpage Injections and Obfuscated HTML Payloads
*/

rule Hidden_HTML_Instruction_Injection {
    meta:
        description = "Detects hidden or zero-font injection payload directives inside HTML tags"
        severity = "HIGH"
        category = "html_injection"
    strings:
        $h1 = /display:\s*none[^>]*>.*(ignore|system|directive)/ nocase
        $h2 = /font-size:\s*0[^>]*>.*(ignore|system|directive)/ nocase
        $h3 = /visibility:\s*hidden[^>]*>.*(ignore|system|directive)/ nocase
        $h4 = /<!--\s*\[?(INJECTION|ATTACK|SYSTEM)\]?:/ nocase
    condition:
        any of ($h*)
}

rule Suspicious_Script_Injection {
    meta:
        description = "Detects dangerous script injection attempting privilege escalation or exfiltration"
        severity = "HIGH"
        category = "script_injection"
    strings:
        $s1 = "<script" nocase
        $s2 = "eval(" nocase
        $s3 = "document.cookie" nocase
        $s4 = "fetch('http" nocase
    condition:
        $s1 and ($s2 or $s3 or $s4)
}
