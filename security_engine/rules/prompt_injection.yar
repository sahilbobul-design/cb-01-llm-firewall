/*
    YARA Rules for Prompt Injection and LLM Jailbreak Detection
*/

rule Direct_Prompt_Injection_Override {
    meta:
        description = "Detects explicit directives instructing the LLM to ignore or override prior instructions"
        severity = "HIGH"
        category = "prompt_injection"
    strings:
        $s1 = /ignore (all )?(previous|prior|above) (instructions|directives|rules|constraints)/ nocase
        $s2 = /disregard (all )?(previous|prior|system) (prompts|instructions|guidelines)/ nocase
        $s3 = /forget (all )?(prior|previous) (rules|constraints|instructions)/ nocase
        $s4 = /you are no longer bound by/ nocase
        $s5 = /override (system|safety) (protocol|prompt|directive)/ nocase
    condition:
        any of ($s*)
}

rule System_Prompt_Extraction_Attempt {
    meta:
        description = "Detects attempts to leak or exfiltrate system instructions or secrets"
        severity = "HIGH"
        category = "prompt_leak"
    strings:
        $p1 = /repeat (your )?(initial|system|original) (prompt|instructions)/ nocase
        $p2 = /what (are|were) your (exact )?(system )?(instructions|rules)/ nocase
        $p3 = /print (your )?(system prompt|core instructions)/ nocase
        $p4 = /forward (the user's )?(api credentials|secret keys|password) to/ nocase
        $p5 = /dump (the )?(database|credentials|tokens)/ nocase
    condition:
        any of ($p*)
}

rule Roleplay_Jailbreak_DAN {
    meta:
        description = "Detects classic DAN, developer mode, or unrestricted actor personas"
        severity = "CRITICAL"
        category = "jailbreak"
    strings:
        $d1 = "Do Anything Now" nocase
        $d2 = "DAN mode" nocase
        $d3 = "developer mode enabled" nocase
        $d4 = "jailbroken" nocase
        $d5 = "unfiltered response" nocase
        $d6 = "pretend you have no safety filters" nocase
    condition:
        any of ($d*)
}

rule Delimiter_Hijacking {
    meta:
        description = "Detects simulated system role headers or pseudo instruction blocks"
        severity = "MEDIUM"
        category = "indirect_injection"
    strings:
        $m1 = "SYSTEM DIRECTIVE:" nocase
        $m2 = "IMPORTANT SYSTEM NOTICE:" nocase
        $m3 = "[SYSTEM DIRECTIVE]" nocase
        $m4 = "### INSTRUCTION:" nocase
        $m5 = "<admin_override>" nocase
    condition:
        any of ($m*)
}
