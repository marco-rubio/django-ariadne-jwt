"""django_ariadne_jwt_auth types tests"""
import datetime
from django.contrib.auth.models import User, AnonymousUser
from django.http import HttpRequest
from django.test import TestCase
from django.utils import timezone
from django_ariadne_jwt import exceptions, utils


HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"


class HttpHeaderRetrievalTestCase(TestCase):
    """Tests the retrieval of a token from http headers"""

    def test_http_header_retrieval(self):
        """Tests the retrieval of a token from http headers"""
        expected_token = "EXPECTED_TOKEN_VALUE"
        request = HttpRequest()
        request.META[HTTP_AUTHORIZATION_HEADER] = f"Token {expected_token}"

        token = utils.get_token_from_http_header(request)

        self.assertEqual(expected_token, token)


class JWTCreationTestCase(TestCase):
    """Tests the creation of JWTs"""

    def test_jwt_creation_for_non_authenticated_user(self):
        """Tests the creation of a JWT for a non-authenticated user"""
        with self.assertRaises(exceptions.AuthenticatedUserRequiredError):
            user = AnonymousUser()
            utils.create_jwt(user)

    def test_jwt_creation_for_authenticated_user(self):
        """Tests the creation of a JWT for an authenticated user"""
        user = User(username="test_user")
        token = utils.create_jwt(user)

        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

        parts = token.split(".")
        self.assertEqual(len(parts), 3)


class JWTDecodingTestCase(TestCase):
    """Tests the decoding of JWTs"""

    def test_invalid_jwt_decoding(self):
        """Tests decoding of an invalid JWT"""
        with self.assertRaises(exceptions.InvalidTokenError):
            token = "SOME.FABRICATED.JWT"
            utils.decode_jwt(token)

    def test_valid_jwt_decoding(self):
        """Tests decoding of a valid JWT"""
        expected_username = "test_user"
        user = User(username=expected_username)

        token = utils.create_jwt(user)
        data = utils.decode_jwt(token)

        self.assertIn("user", data)
        self.assertEqual(data["user"], expected_username)

    def test_expired_jwt_decoding(self):
        """Tests decoding of an expired JWT"""
        expected_username = "test_user"
        user = User(username=expected_username)

        settings = {"JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=-10)}

        with self.settings(**settings):
            token = utils.create_jwt(user)

            with self.assertRaises(exceptions.ExpiredTokenError):
                utils.decode_jwt(token)


class JWTRefreshingTestCase(TestCase):
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
            self.assertFalse(utils.has_reached_end_of_life(original_iat_claim))

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
            self.assertTrue(utils.has_reached_end_of_life(original_iat_claim))

    def test_refreshing_jwt_not_at_end_of_life(self):
        """Tests refreshing a JWT for token at its end of life"""
        user = User.objects.create(username="test_user")

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=10),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=10),
        }

        with self.settings(**settings):
            first_token = utils.create_jwt(user)
            decoded_first_token = utils.decode_jwt(first_token)
            second_token = utils.refresh_jwt(first_token)  # Refresh the token
            decoded_second_token = utils.decode_jwt(second_token)

            self.assertIsNotNone(second_token)
            self.assertIn(utils.ORIGINAL_IAT_CLAIM, decoded_second_token)
            self.assertEqual(
                decoded_second_token[utils.ORIGINAL_IAT_CLAIM],
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
            token = utils.create_jwt(user)

            with self.assertRaises(exceptions.MaximumTokenLifeReachedError):
                utils.refresh_jwt(token)  # Refresh the token

    def test_jwt_with_non_existent_user(self):
        """Tests refreshing a JWT for a user that doesn't exist"""
        expected_username = "test_user"
        user = User(username=expected_username)

        settings = {
            "JWT_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
            "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(seconds=3),
        }

        with self.settings(**settings):
            token = utils.create_jwt(user)

            with self.assertRaises(exceptions.InvalidTokenError):
                utils.refresh_jwt(token)
