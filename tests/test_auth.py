"""Tests for authentication and password utilities."""

import pytest

from sentriq.auth import (
    hash_password,
    verify_password,
    validate_password_strength,
    user_role,
    can_create_alert,
    can_edit_alert,
    can_delete_alert,
    can_manage_users,
    can_escalate_alert,
    can_assign_alert,
    assignable_roles_for,
)
from sentriq.models import User


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password(self):
        hashed = hash_password("TestPass123!")
        assert hashed.startswith("pbkdf2_sha256$")
        assert len(hashed.split("$")) == 3

    def test_hash_password_with_salt(self):
        salt = "test_salt_123"
        hashed1 = hash_password("TestPass123!", salt)
        hashed2 = hash_password("TestPass123!", salt)
        assert hashed1 == hashed2

    def test_hash_password_different_salts(self):
        hashed1 = hash_password("TestPass123!")
        hashed2 = hash_password("TestPass123!")
        assert hashed1 != hashed2  # Different random salts

    def test_verify_password_correct(self):
        password = "TestPass123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        hashed = hash_password("TestPass123!")
        assert verify_password("WrongPass123!", hashed) is False

    def test_verify_password_invalid_hash(self):
        assert verify_password("TestPass123!", "invalid_hash") is False
        assert verify_password("TestPass123!", "") is False


class TestPasswordStrength:
    """Test password strength validation."""

    def test_valid_password(self):
        assert validate_password_strength("TestPass123!") is None

    def test_too_short(self):
        result = validate_password_strength("Short1!")
        assert result is not None
        assert "10 characters" in result

    def test_no_uppercase(self):
        result = validate_password_strength("testpass123!")
        assert result is not None
        assert "uppercase" in result

    def test_no_lowercase(self):
        result = validate_password_strength("TESTPASS123!")
        assert result is not None
        assert "lowercase" in result

    def test_no_number(self):
        result = validate_password_strength("TestPassWord!")
        assert result is not None
        assert "number" in result

    def test_no_symbol(self):
        result = validate_password_strength("TestPass1234")
        assert result is not None
        assert "symbol" in result


class TestUserRole:
    """Test role determination."""

    def test_l1_role(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert user_role(user) == "L1"

    def test_l2_role(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert user_role(user) == "L2"

    def test_l3_role(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert user_role(user) == "L3"

    def test_admin_role(self):
        user = User(username="admin", role="L1", is_admin=True)
        assert user_role(user) == "L3"  # Admin always gets L3


class TestPermissions:
    """Test RBAC permissions."""

    def test_l1_can_create_alert(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert can_create_alert(user) is True

    def test_l2_can_create_alert(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert can_create_alert(user) is True

    def test_l3_can_create_alert(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert can_create_alert(user) is True

    def test_l1_cannot_delete_alert(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert can_delete_alert(user) is False

    def test_l2_cannot_delete_alert(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert can_delete_alert(user) is False

    def test_l3_can_delete_alert(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert can_delete_alert(user) is True

    def test_admin_can_delete_alert(self):
        user = User(username="admin", role="L1", is_admin=True)
        assert can_delete_alert(user) is True

    def test_l1_cannot_manage_users(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert can_manage_users(user) is False

    def test_l2_cannot_manage_users(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert can_manage_users(user) is False

    def test_l3_can_manage_users(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert can_manage_users(user) is True

    def test_l1_can_escalate(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert can_escalate_alert(user) is True

    def test_l2_can_escalate(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert can_escalate_alert(user) is True

    def test_l3_cannot_escalate(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert can_escalate_alert(user) is False

    def test_l1_cannot_assign(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert can_assign_alert(user) is False

    def test_l2_can_assign(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert can_assign_alert(user) is True

    def test_l3_can_assign(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert can_assign_alert(user) is True


class TestAssignableRoles:
    """Test assignable roles for each user role."""

    def test_l1_assignable_roles(self):
        user = User(username="l1", role="L1", is_admin=False)
        assert assignable_roles_for(user) == []

    def test_l2_assignable_roles(self):
        user = User(username="l2", role="L2", is_admin=False)
        assert assignable_roles_for(user) == ["L1"]

    def test_l3_assignable_roles(self):
        user = User(username="l3", role="L3", is_admin=False)
        assert assignable_roles_for(user) == ["L1", "L2"]

    def test_admin_assignable_roles(self):
        user = User(username="admin", role="L1", is_admin=True)
        assert assignable_roles_for(user) == ["L1", "L2"]


class TestEditPermissions:
    """Test alert edit permissions."""

    def _make_alert(self, status="Open"):
        """Create a mock alert."""
        from unittest.mock import MagicMock
        alert = MagicMock()
        alert.status = status
        return alert

    def test_l1_can_edit_new_alert(self):
        user = User(username="l1", role="L1", is_admin=False)
        alert = self._make_alert("Open")
        assert can_edit_alert(user, alert) is True

    def test_l1_can_edit_investigating_alert(self):
        user = User(username="l1", role="L1", is_admin=False)
        alert = self._make_alert("WIP")
        assert can_edit_alert(user, alert) is True

    def test_l1_cannot_edit_closed_alert(self):
        user = User(username="l1", role="L1", is_admin=False)
        alert = self._make_alert("Closed")
        assert can_edit_alert(user, alert) is False

    def test_l2_can_edit_wip_alert(self):
        user = User(username="l2", role="L2", is_admin=False)
        alert = self._make_alert("WIP")
        assert can_edit_alert(user, alert) is True

    def test_l3_can_edit_any_alert(self):
        user = User(username="l3", role="L3", is_admin=False)
        for status in ["Open", "Pending", "WIP", "Closed"]:
            alert = self._make_alert(status)
            assert can_edit_alert(user, alert) is True
