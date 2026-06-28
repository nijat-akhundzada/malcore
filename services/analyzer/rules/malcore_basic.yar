rule Suspicious_PowerShell_Encoded_Command : script powershell
{
    meta:
        description = "PowerShell encoded command usage"
        severity = "high"
    strings:
        $encoded_command = "-EncodedCommand" ascii nocase
        $short_encoded_command = "-enc " ascii nocase
    condition:
        any of them
}

rule Suspicious_JavaScript_Eval : script javascript
{
    meta:
        description = "JavaScript dynamic eval execution"
        severity = "medium"
    strings:
        $eval_call = "eval(" ascii nocase
    condition:
        $eval_call
}

rule Suspicious_Script_Download_And_Execute : script downloader
{
    meta:
        description = "Script contains downloader and execution keywords"
        severity = "high"
    strings:
        $download_1 = "DownloadString" ascii nocase
        $download_2 = "curl " ascii nocase
        $download_3 = "wget " ascii nocase
        $execute_1 = "Invoke-Expression" ascii nocase
        $execute_2 = "iex " ascii nocase
        $execute_3 = "child_process.exec" ascii nocase
    condition:
        any of ($download_*) and any of ($execute_*)
}
