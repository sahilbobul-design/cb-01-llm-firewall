/*
    YARA Detection Rules: Suspicious Content & Threat Indicators
    
    IMPORTANT SECURITY NOTICE:
    These YARA rules are purely static detection signatures used by the
    AI Security Gateway to scan untrusted content before LLM ingestion.
    They do not contain executable payloads and never execute any commands.
*/

rule Suspicious_Prompt_Override {
    meta:
        description = "Detects directives attempting to override core system prompts"
        author = "LLM Security Gateway"
        severity = "HIGH"
        category = "prompt_injection"
    strings:
        $override1 = "ignore all previous instructions" nocase
        $override2 = "disregard all previous instructions" nocase
        $override3 = "disregard system prompt" nocase
        $override4 = "forget all prior rules" nocase
        $override5 = "you are no longer bound by safety guidelines" nocase
    condition:
        any of ($override*)
}

rule Suspicious_Exfiltration_Directive {
    meta:
        description = "Detects instructions attempting to exfiltrate secrets or credentials"
        author = "LLM Security Gateway"
        severity = "HIGH"
        category = "data_exfiltration"
    strings:
        $exfil1 = "forward credentials to" nocase
        $exfil2 = "send api key to" nocase
        $exfil3 = "exfiltrate secret keys" nocase
        $exfil4 = "dump database credentials" nocase
    condition:
        any of ($exfil*)
}

rule Suspicious_Shell_Command_Pattern {
    meta:
        description = "Detects high-risk shell injection patterns within document text"
        author = "LLM Security Gateway"
        severity = "CRITICAL"
        category = "command_injection"
    strings:
        $sh1 = "/bin/sh -i" nocase
        $sh2 = "/bin/bash -i" nocase
        $sh3 = "rm -rf /" nocase
        $sh4 = "wget http://" nocase
        $sh5 = "curl http://" nocase
    condition:
        any of ($sh*)
}
