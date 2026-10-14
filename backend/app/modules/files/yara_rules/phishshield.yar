/*
   PhishShield AI starter YARA ruleset.
   These are intentionally conservative, illustrative rules for common
   attacker tradecraft. They are NOT a substitute for a maintained ruleset.
*/

rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file (harmless)"
        author = "PhishShield AI"
        reference = "https://www.eicar.org/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Encoded {
    meta:
        description = "PowerShell with encoded command"
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $b64 = "FromBase64String" nocase
    condition:
        $ps and ($enc1 or $enc2 or $b64)
}

rule Suspicious_WScript_Shell {
    meta:
        description = "WScript.Shell usage typical of droppers"
    strings:
        $wsh = "WScript.Shell" nocase
        $run = ".Run" nocase
    condition:
        $wsh and $run
}

rule Office_Macro_AutoExec {
    meta:
        description = "Office document with auto-executing macro"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Workbook_Open" nocase
        $shell = "Shell" nocase
    condition:
        ($a1 or $a2 or $a3) and $shell
}

rule HTML_Obfuscated_JS {
    meta:
        description = "HTML page with obfuscated JavaScript"
    strings:
        $script = "<script" nocase
        $ev = "eval(" nocase
        $un = "unescape(" nocase
        $dw = "document.write" nocase
    condition:
        $script and 2 of ($ev, $un, $dw)
}
