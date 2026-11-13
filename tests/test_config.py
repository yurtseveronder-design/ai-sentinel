import pytest

from ai_sentinel.config import load_config


def test_loads_valid_yaml(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("version: '1'\nrules: [a, b]\n")
    assert load_config(f) == {"version": "1", "rules": ["a", "b"]}


def test_missing_path_argument():
    with pytest.raises(FileNotFoundError):
        load_config()


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yaml")


@pytest.mark.parametrize("content", ["", "   \n", "# only a comment\n"])
def test_empty_config_rejected(tmp_path, content):
    f = tmp_path / "c.yaml"
    f.write_text(content)
    with pytest.raises(ValueError):
        load_config(f)


def test_invalid_yaml_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("a: [unclosed\n")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(f)


def test_non_mapping_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("- just\n- a list\n")
    with pytest.raises(ValueError, match="dictionary"):
        load_config(f)


def test_bundled_signatures_file_loads():
    from pathlib import Path
    import ai_sentinel

    path = Path(ai_sentinel.__file__).parent / "threat_signatures.yaml"
    assert "legacy_exact_matches" in load_config(path)
