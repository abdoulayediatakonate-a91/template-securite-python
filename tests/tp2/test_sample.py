import pytest
import hashlib


from tp2.utils.sample import Sample


@pytest.mark.parametrize(
    "contenu, entropie_attendue",
    [
        (b"", 0.0),
        (b"AAAA", 0.0),
        (b"AABB", 1.0),
    ],
)
def test_shannon_entropy(tmp_path, contenu, entropie_attendue):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(contenu)
    sample = Sample(str(fichier))

    assert sample.shannon_entropy() == pytest.approx(entropie_attendue)


def test_extract_iocs_filtre_et_dedoublonne_les_ips(tmp_path):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(
        b"192.0.2.10 999.999.999.999 192.0.2.10"
    )
    sample = Sample(str(fichier))

    resultat = sample.extract_iocs()

    assert resultat["ips"] == ["192.0.2.10"]

def test_get_file_metadata(tmp_path):
    contenu = b"Exemple de contenu pour le TP2"
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(contenu)
    sample = Sample(str(fichier))

    resultat = sample.get_file_metadata()

    assert resultat["size"] == len(contenu)
    assert resultat["sha256"] == hashlib.sha256(contenu).hexdigest()
    assert resultat["md5"] == hashlib.md5(contenu).hexdigest()
    assert resultat["entropy"] == pytest.approx(sample.shannon_entropy())
    assert isinstance(resultat["file_type"], str)
    assert resultat["file_type"]

def test_extract_iocs_urls_et_domaines(tmp_path):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(
        b"https://example.org/test "
        b"https://example.org/test "
        b"http://192.0.2.10/page"
    )
    sample = Sample(str(fichier))

    resultat = sample.extract_iocs()

    assert resultat["urls"] == [
        "http://192.0.2.10/page",
        "https://example.org/test",
    ]
    assert resultat["domains"] == ["example.org"]
