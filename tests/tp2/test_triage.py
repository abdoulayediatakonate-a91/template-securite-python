import json

from tp2.utils.report import Report
from pathlib import Path
from tp2.utils.triage import Triage

def test_triage_run(tmp_path):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(
        b"powershell.exe -EncodedCommand VABFAFMAVAA= "
        b"https://example.org/test 192.0.2.10"
    )

    racine = Path(__file__).resolve().parents[2]
    regles = racine / "rules" / "personal_rules.yar"

    triage = Triage(
        path=str(fichier),
        backend="ollama",
        rules_path=str(regles),
    )

    resultat = triage.run()

    assert resultat["size"] == fichier.stat().st_size
    assert resultat["iocs"]["ips"] == ["192.0.2.10"]
    assert resultat["iocs"]["domains"] == ["example.org"]
    assert resultat["yara_matches"] == ["PowerShell_EncodedCommand"]
    assert resultat["binary_format"] is None
    assert resultat["imports"] == []
    assert resultat["exports"] == []
    assert resultat["sections"] == []
    assert resultat["family_guess"] == "indeterminee"
    assert resultat["mitre_attack"] == []
    assert resultat["score"] == 3
    assert "hors ligne" in resultat["llm_summary"]

def test_triage_genere_un_json(tmp_path):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(b"https://example.org/test 192.0.2.10")

    racine = Path(__file__).resolve().parents[2]
    regles = racine / "rules" / "personal_rules.yar"

    triage = Triage(
        path=str(fichier),
        backend="ollama",
        rules_path=str(regles),
    )
    resultat = triage.run()

    destination = tmp_path / "exemple.bin.triage.json"
    Report(resultat).generate_json(str(destination))

    with destination.open("r", encoding="utf-8") as fichier_json:
        contenu = json.load(fichier_json)

    assert contenu == resultat
    assert contenu["iocs"]["ips"] == ["192.0.2.10"]
    assert contenu["yara_matches"] == []