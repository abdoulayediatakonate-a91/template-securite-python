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

def test_generate_pdf(tmp_path):
    resultat = {
        "size": 42,
        "llm_summary": "Analyse hors ligne de démonstration.",
        "score": 0,
        "iocs": {},
        "yara_matches": [],
    }
    destination = tmp_path / "rapport.pdf"

    Report(resultat).generate_pdf(str(destination))

    contenu = destination.read_bytes()

    assert contenu.startswith(b"%PDF-")
    assert b"%%EOF" in contenu[-1024:]
