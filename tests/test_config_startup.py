import pytest
from ai_sentinel.core.shield import SecurityShield

def test_missing_explicit_config_raises():
    with pytest.raises((FileNotFoundError, ValueError)):
        SecurityShield(config_path="non_existent_config_path_9999.yaml")

def test_empty_config_raises(tmp_path):
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("")
    with pytest.raises((ValueError, FileNotFoundError)):
        SecurityShield(config_path=str(empty_file))

def test_invalid_yaml_config_raises(tmp_path):
    invalid_file = tmp_path / "invalid.yaml"
    invalid_file.write_text("invalid: [unclosed bracket")
    with pytest.raises((ValueError, Exception)):
        SecurityShield(config_path=str(invalid_file))