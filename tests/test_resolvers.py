"""django_ariadne_jwt_auth resolvers tests"""
import datetime
from dataclasses import dataclass
from django.contrib.auth.models import User
from django.http import HttpRequest
from django.test import TestCase
from django_ariadne_jwt import resolvers, utils


@dataclass
class InfoObject(object):
    context: HttpRequest


class TokenGenerationTestCase(TestCase):
    """Tests for the token generation functionality"""

    def setUp(self):
        self.user_data = {"username": "pepe", "password": "lame_password"}

        self.user = User.objects.create(**self.user_data)
        self.user.set_password(self.user_data["password"])
        self.user.save()

    def test_token_auth_generation_with_valid_credentials(self):
        """Test the generation of a token for valid credentials"""
        request = HttpRequest()
        info = InfoObject(context=request)
        credentials = self.user_data

        resolved_data = resolvers.resolve_token_auth(None, info, **credentials)

        self.assertIsNotNone(resolved_data)
        self.assertIsInstance(resolved_data, dict)
        self.assertIn("token", resolved_data)
        self.assertIsInstance(resolved_data["token"], str)

    def test_token_auth_generation_with_invalid_credentials(self):
        """Test the generation of an empty token for invalid credentials"""
        request = HttpRequest()
        info = InfoObject(context=request)
        credentials = self.user_data
        credentials["password"] = "BAAAAAD PASSWORD!"

        resolved_data = resolvers.resolve_token_auth(None, info, **credentials)

        self.assertIsNotNone(resolved_data)
        self.assertIsInstance(resolved_data, dict)
        self.assertIn("token", resolved_data)
        self.assertIsNone(resolved_data["token"])


class TokenRefreshingTestCase(TestCase):
    """Tests for the token resfresh functionality"""

    def setUp(self):
        self.user_data = {"username": "pepe", "password": "lame_password"}

        self.user = User.objects.create(**self.user_data)
        self.user.set_password(self.user_data["password"])
        self.user.save()

    def test_refreshing_for_valid_token(self):
        """Test refreshing a valid token"""
        info = InfoObject(context=HttpRequest())
        token = utils.create_jwt(self.user)

        resolved_data = resolvers.resolve_refresh_token(None, info, token)

        self.assertIsNotNone(resolved_data)
        self.assertIn("token", resolved_data)
        self.assertIsInstance(resolved_data["token"], str)

    def test_refreshing_token_at_end_of_life(self):
        """Test refreshing a token which is at its end of life"""
        request = HttpRequest()
        info = InfoObject(context=request)

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=0),
        }

        with self.settings(**settings):
            token = utils.create_jwt(self.user)
            resolved_data = resolvers.resolve_refresh_token(None, info, token)

            self.assertIsNotNone(resolved_data)
            self.assertIn("token", resolved_data)
            self.assertIsNone(resolved_data["token"])

    def test_refreshing_token_not_at_end_of_life(self):
        """Test refreshing a token which is at its end of life"""
        request = HttpRequest()
        info = InfoObject(context=request)

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=1),
        }

        with self.settings(**settings):
            token = utils.create_jwt(self.user)
            resolved_data = resolvers.resolve_refresh_token(None, info, token)

            self.assertIsNotNone(resolved_data)
            self.assertIn("token", resolved_data)
            self.assertIsInstance(resolved_data["token"], str)


class TokenVerificationTestCase(TestCase):
    """Tests for the token verification functionality"""

    def setUp(self):
        self.user_data = {"username": "pepe", "password": "lame_password"}

        self.user = User.objects.create(**self.user_data)
        self.user.set_password(self.user_data["password"])
        self.user.save()

    def test_verification_for_invalid_token(self):
        """Test verification of an invalid token"""
        request = HttpRequest()
        info = InfoObject(context=request)

        token = "SOME.FABRICATED.JWT"
        resolved_data = resolvers.resolve_verify_token(None, info, token)

        self.assertIsNotNone(resolved_data)
        self.assertIn("valid", resolved_data)
        self.assertFalse(resolved_data["valid"])
        self.assertNotIn("username", resolved_data)

    def test_verification_for_expired_token(self):
        """Test verification of an expired token"""
        request = HttpRequest()
        info = InfoObject(context=request)

        settings = {"JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=-10)}

        with self.settings(**settings):
            token = utils.create_jwt(self.user)
            resolved_data = resolvers.resolve_verify_token(None, info, token)

            self.assertIsNotNone(resolved_data)
            self.assertIn("valid", resolved_data)
            self.assertFalse(resolved_data["valid"])
            self.assertNotIn("username", resolved_data)

    def test_verification_for_valid_token(self):
        """Test verification of a valid token"""
        request = HttpRequest()
        info = InfoObject(context=request)

        settings = {"JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=2)}

        with self.settings(**settings):
            token = utils.create_jwt(self.user)
            resolved_data = resolvers.resolve_verify_token(None, info, token)

            self.assertIsNotNone(resolved_data)
            self.assertIn("valid", resolved_data)
            self.assertTrue(resolved_data["valid"])
            self.assertIn("user", resolved_data)
            self.assertEqual(resolved_data["user"], self.user_data["username"])
