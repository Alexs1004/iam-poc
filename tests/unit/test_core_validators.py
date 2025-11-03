import pytest

from app.core import validators


class TestNormalizeUsername:
    def test_normalizes_and_validates(self):
        assert validators.normalize_username("  Alice.Example  ") == "alice.example"

    @pytest.mark.parametrize(
        "raw, message",
        [
            ("ab", "Username must be at least 3 characters"),
            ("a" * 65, "Username must not exceed 64 characters"),
            ("_alice", "Username cannot start or end with special characters"),
            ("alice-", "Username cannot start or end with special characters"),
        ],
    )
    def test_invalid_cases(self, raw, message):
        with pytest.raises(ValueError, match=message):
            validators.normalize_username(raw)


class TestValidateEmail:
    def test_returns_lowercased_email(self):
        assert validators.validate_email("  USER@Example.COM ") == "user@example.com"

    @pytest.mark.parametrize(
        "email",
        ["", "no-at-symbol", "user@", "@domain.com", "user@example", "a" * 255 + "@example.com"],
    )
    def test_invalid_email_formats(self, email):
        with pytest.raises(ValueError):
            validators.validate_email(email)


class TestValidateName:
    def test_valid_name_passes(self):
        assert validators.validate_name(" Alice ", "First name") == "Alice"

    @pytest.mark.parametrize(
        "name, message",
        [
            ("", "First name is required"),
            ("a" * 129, "First name exceeds maximum length"),
            ("Alice<script>", "First name contains invalid characters"),
        ],
    )
    def test_invalid_names(self, name, message):
        with pytest.raises(ValueError, match=message):
            validators.validate_name(name, "First name")
