"""django_ariadne_jwt_auth backends tests"""
import datetime
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User, AnonymousUser
from django.http import HttpRequest
from django.test import TestCase
from django.utils import timezone
from django_ariadne_jwt import exceptions
from django_ariadne_jwt.backends import JSONWebTokenBackend

HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"


class BaseBackendTestCase(TestCase):
    def setUp(self):
        super().setUp()
        self.backend = JSONWebTokenBackend()


class BackendTestCase(BaseBackendTestCase):
    """Tests for the JWT backend"""

    def setUp(self):
        User = get_user_model()

        self.user_data = {
            User.USERNAME_FIELD: "test_user",
            "password": "lame_password",
        }

        self.user = User.objects.create(**self.user_data)
        self.user.set_password(self.user_data["password"])
        self.user.save()

    def test_authentication_with_valid_token(self):
        """Tests the authentication of a user from a valid token"""
        token = self.backend.create(self.user)
        request = HttpRequest()

        settings = {
            "AUTHENTICATION_BACKENDS": (
                "django_ariadne_jwt.backends.JSONWebTokenBackend",
            )
        }

        with self.settings(**settings):
            user = authenticate(request, token=token)
            self.assertIsNotNone(user)
            self.assertEqual(user, self.user)

    def test_existing_user_retrieval(self):
        """Tests the retrieval of an existing user"""
        user = self.backend.get_user(self.user.pk)
        self.assertEqual(user, self.user)

    def test_non_existing_user_retrieval(self):
        """Tests the retrieval of a non existing user"""
        user = self.backend.get_user(-1)
        self.assertIsNone(user)


class HttpHeaderRetrievalTestCase(BaseBackendTestCase):
    """Tests the retrieval of a token from http headers"""

    def test_http_header_retrieval(self):
        """Tests the retrieval of a token from http headers"""
        expected_token = "EXPECTED_TOKEN_VALUE"
        request = HttpRequest()
        request.META[HTTP_AUTHORIZATION_HEADER] = f"Token {expected_token}"

        token = self.backend.get_token_from_http_header(request)

        self.assertEqual(expected_token, token)


class JWTCreationTestCase(BaseBackendTestCase):
    """Tests the creation of JWTs"""

    def test_jwt_creation_for_non_authenticated_user(self):
        """Tests the creation of a JWT for a non-authenticated user"""
        with self.assertRaises(exceptions.AuthenticatedUserRequiredError):
            user = AnonymousUser()
            self.backend.create(user)

    def test_jwt_creation_for_authenticated_user(self):
        """Tests the creation of a JWT for an authenticated user"""
        user = User(username="test_user")
        token = self.backend.create(user)

        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

        parts = token.split(".")
        self.assertEqual(len(parts), 3)


class JWTDecodingTestCase(BaseBackendTestCase):
    """Tests the decoding of JWTs"""

    def test_invalid_jwt_decoding(self):
        """Tests decoding of an invalid JWT"""
        with self.assertRaises(exceptions.InvalidTokenError):
            token = "SOME.FABRICATED.JWT"
            self.backend.decode(token)

    def test_valid_jwt_decoding(self):
        """Tests decoding of a valid JWT"""
        expected_username = "test_user"
        user = User(username=expected_username)

        token = self.backend.create(user)
        data = self.backend.decode(token)

        self.assertIn("user", data)
        self.assertEqual(data["user"], expected_username)

    def test_expired_jwt_decoding(self):
        """Tests decoding of an expired JWT"""
        expected_username = "test_user"
        user = User(username=expected_username)

        settings = {"JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=-10)}

        with self.settings(**settings):
            token = self.backend.create(user)

            with self.assertRaises(exceptions.ExpiredTokenError):
                self.backend.decode(token)


class JWTRefreshingTestCase(BaseBackendTestCase):
    """Tests the refreshing of JWTs"""

    def test_token_not_at_end_of_life_detection(self):
        """Tests the detection of a token which is at its end of life"""
        now = timezone.localtime()
        delta = 5

        original_iat_claim = (
            now - datetime.timedelta(minutes=delta, seconds=-1)
        ).timestamp()

        settings = {
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(minutes=delta)
        }

        with self.settings(**settings):
            self.assertFalse(
                self.backend.has_reached_end_of_life(original_iat_claim)
            )

    def test_token_at_end_of_life_detection(self):
        """Tests the detection of a token which isn't yet at its end of life"""
        now = timezone.localtime()
        delta = 5

        original_iat_claim = (
            now - datetime.timedelta(minutes=delta, seconds=1)
        ).timestamp()

        settings = {
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(minutes=delta)
        }

        with self.settings(**settings):
            self.assertTrue(
                self.backend.has_reached_end_of_life(original_iat_claim)
            )

    def test_refreshing_jwt_not_at_end_of_life(self):
        """Tests refreshing a JWT for token at its end of life"""
        user = User.objects.create(username="test_user")

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=10),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=10),
        }

        with self.settings(**settings):
            first_token = self.backend.create(user)
            decoded_first_token = self.backend.decode(first_token)
            second_token = self.backend.refresh(
                first_token
            )  # Refresh the token
            decoded_second_token = self.backend.decode(second_token)

            self.assertIsNotNone(second_token)
            self.assertIn(
                self.backend.ORIGINAL_IAT_CLAIM, decoded_second_token
            )
            self.assertEqual(
                decoded_second_token[self.backend.ORIGINAL_IAT_CLAIM],
                decoded_first_token["iat"],
            )

    def test_refreshing_jwt_at_end_of_life(self):
        """Tests refreshing a JWT for token at its end of life"""
        user = User.objects.create(username="test_user")

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=0),
        }

        with self.settings(**settings):
            token = self.backend.create(user)

            with self.assertRaises(exceptions.MaximumTokenLifeReachedError):
                self.backend.refresh(token)  # Refresh the token

    def test_jwt_with_non_existent_user(self):
        """Tests refreshing a JWT for a user that doesn't exist"""
        expected_username = "test_user"
        user = User(username=expected_username)

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
        }

        with self.settings(**settings):
            token = self.backend.create(user)

            with self.assertRaises(exceptions.InvalidTokenError):
                self.backend.refresh(token)
