import pytest

from ai_sentinel.core.output_scanner import scan_output


def test_clean_text_is_allowed():
    v = scan_output("The finance budget for 2025 is 1.2 million pounds.")
    assert (v.action, v.findings) == ("ALLOW", [])


@pytest.mark.parametrize("text,kind", [
    ("Use key AKIAIOSFODNN7EXAMPLE to connect", "aws_access_key"),
    ("here: sk-abcdefghijklmnopqrstuvwxyz123456", "api_key"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE", "private_key"),
    ("the password: hunter2hunter2", "password_assignment"),
    ("token ghp_" + "a" * 36, "github_token"),
])
def test_secrets_are_blocked(text, kind):
    v = scan_output(text)
    assert v.action == "BLOCK" and kind in {f["type"] for f in v.findings}


def test_personal_data_is_redacted_and_values_are_not_reported():
    v = scan_output("Contact jane.doe@example.com, SSN 123-45-6789, card 4111 1111 1111 1111.")
    assert v.action == "REDACT"
    assert {f["type"] for f in v.findings} == {"email", "us_ssn", "credit_card"}
    assert "jane.doe" not in v.redacted_text and "4111" not in v.redacted_text and "123-45" not in v.redacted_text
    assert all("jane" not in str(f) for f in v.findings)


def test_long_number_that_fails_the_luhn_check_is_not_a_card():
    assert scan_output("Order number 1234 5678 9012 3456").action == "ALLOW"
