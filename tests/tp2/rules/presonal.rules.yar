rule PowerShell_EncodedCommand
{
    meta:
        description = "Presence de PowerShell et de l'option EncodedCommand"

    strings:
        $powershell = "powershell" ascii wide nocase fullword
        $encoded = "-EncodedCommand" ascii wide nocase fullword

    condition:
        $powershell and $encoded
}