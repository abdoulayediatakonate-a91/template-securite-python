import json

from tp2.utils.report import Report


def test_generate_json(tmp_path):
    resultat = {
        "sha256": "empreinte-de-test",
        "size": 42,
        "iocs": {
            "domains": ["example.org"],
            "ips": ["192.0.2.10"],
            "urls": [],
            "mutex": [],
            "registry": [],
        },
        "yara_matches": ["PowerShell_EncodedCommand"],
        "llm_summary": "Échantillon de test, sans exécution.",
    }
    destination = tmp_path / "rapport.json"
    rapport = Report(resultat)

    rapport.generate_json(str(destination))

    assert destination.is_file()

    with destination.open("r", encoding="utf-8") as fichier:
        contenu = json.load(fichier)

    assert contenu == resultat
