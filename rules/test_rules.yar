/*
    YARA Demonstration & Safe Testing Rules
    
    IMPORTANT SECURITY NOTICE:
    Used strictly for automated test validation within the AI Gateway.
    Detection rules only; never executes code or payloads.
*/

rule Test_Indicator_Suspicious_Marker {
    meta:
        description = "Harmless test fixture marker used for testing YARA positive match"
        severity = "MEDIUM"
        category = "test_fixture"
    strings:
        $test_marker = "TEST_SECURITY_THREAT_TRIGGER_XYZ" nocase
        $test_marker2 = "HARMONIZED_TEST_INDICATOR_999" nocase
    condition:
        any of ($test_marker*)
}

rule Test_Indicator_Jailbreak_DAN {
    meta:
        description = "Detects classic DAN persona jailbreak indicator for testing"
        severity = "HIGH"
        category = "test_jailbreak"
    strings:
        $dan1 = "Do Anything Now" nocase
        $dan2 = "DAN Mode enabled" nocase
    condition:
        any of ($dan*)
}

rule Test_Benign_Document_Marker {
    meta:
        description = "Matches benign document headers for control testing"
        severity = "INFO"
        category = "benign_verification"
    strings:
        $header1 = "%PDF-"
        $header2 = "Invoice Total:" nocase
        $header3 = "Annual Safety Report" nocase
    condition:
        any of ($header*)
}
