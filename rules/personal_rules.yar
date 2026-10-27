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

rule Vssadmin_Delete_Shadows
{
    meta:
        description = "Presence des elements d'une commande de suppression des copies VSS"

    strings:
        $outil = "vssadmin" ascii wide nocase fullword
        $action = "delete" ascii wide nocase fullword
        $cible = "shadows" ascii wide nocase fullword

    condition:
        all of them
}