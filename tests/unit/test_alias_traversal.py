"""Unit tests for traversal alias rejection (alias-poisoning fix)."""

import pytest

from apm_cli.models.dependency.object_fields import parse_alias_override
from apm_cli.utils.path_security import PathTraversalError


class TestParseAliasOverrideTraversal:
    """Reject aliases that navigate outside apm_modules."""

    def test_single_dot_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override(".")

    def test_double_dot_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override("..")

    def test_traversal_segment_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override("foo/../bar")

    def test_leading_dot_slash_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override("./safe-name")

    def test_trailing_dot_dot_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override("pkg/..")

    def test_encoded_dot_dot_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override("%2e%2e")

    def test_double_encoded_dot_dot_rejected(self):
        with pytest.raises((ValueError, PathTraversalError)):
            parse_alias_override("%252e%252e")


class TestParseAliasOverrideSafe:
    """Safe aliases must still be accepted."""

    def test_simple_name(self):
        assert parse_alias_override("my-skill") == "my-skill"

    def test_name_with_dots(self):
        assert parse_alias_override("my-skill.v2") == "my-skill.v2"

    def test_deep_dotted_name(self):
        assert parse_alias_override("deep.nested.name") == "deep.nested.name"

    def test_underscore_and_hyphen(self):
        assert parse_alias_override("skill_v2-beta") == "skill_v2-beta"

    def test_none_returns_none(self):
        assert parse_alias_override(None) is None

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            parse_alias_override("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError):
            parse_alias_override("   ")

    def test_invalid_chars_rejected(self):
        with pytest.raises(ValueError):
            parse_alias_override("bad alias!")
