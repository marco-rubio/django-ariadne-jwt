"""django_ariadne_jwt_auth backends tests"""
from django.contrib.auth import authenticate, get_user_model
from django.http import HttpRequest
from django.test import TestCase
from django_ariadne_jwt import backends


class BackendTestCase(TestCase):
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
        token = backends.JSONWebTokenBackend().create(self.user)
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
        backend = backends.JSONWebTokenBackend()
        user = backend.get_user(self.user.pk)
        self.assertEqual(user, self.user)

    def test_non_existing_user_retrieval(self):
        """Tests the retrieval of a non existing user"""
        backend = backends.JSONWebTokenBackend()
        user = backend.get_user(-1)
        self.assertIsNone(user)
