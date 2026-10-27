import pytest

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