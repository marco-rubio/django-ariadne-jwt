"""django_ariadne_jwt_auth middleware tests"""
import ariadne
from dataclasses import dataclass
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import TestCase
from unittest.mock import Mock, patch
from django_ariadne_jwt.backends import JSONWebTokenBackend
from django_ariadne_jwt.middleware import JSONWebTokenMiddleware

HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"


@dataclass
class InfoObject(object):
    context: HttpRequest


class MiddlewareTestCase(TestCase):
    """Tests for the JWT middleware"""

    def setUp(self):
        User = get_user_model()

        self.user_data = {
            User.USERNAME_FIELD: "test_user",
            "password": "lame_password",
        }

        self.user = User.objects.create(**self.user_data)
        self.user.set_password(self.user_data["password"])
        self.user.save()

        self.other_user_data = {
            User.USERNAME_FIELD: "other_test_user",
            "password": "lame_password",
        }

        self.other_user = User.objects.create(**self.other_user_data)
        self.other_user.set_password(self.other_user_data["password"])
        self.other_user.save()

    def test_without_user_and_with_valid_token(self):
        """Tests resolving with a valid token on a request without user"""
        token = JSONWebTokenBackend().create(self.user)

        request = HttpRequest()
        request.META[HTTP_AUTHORIZATION_HEADER] = f"Token {token}"

        info = InfoObject(context=request)

        def next(root, info, **kwargs):
            self.assertTrue(hasattr(info.context, "user"))
            self.assertEqual(info.context.user, self.user)

        next = Mock(wraps=next)

        settings = {
            "AUTHENTICATION_BACKENDS": (
                "django_ariadne_jwt.backends.JSONWebTokenBackend",
                "django.contrib.auth.backends.ModelBackend",
            )
        }

        with self.settings(**settings):
            middleware = JSONWebTokenMiddleware()
            middleware.resolve(next, {}, info)

            self.assertTrue(next.called)

    def test_with_user_and_valid_token(self):
        """Tests that the middleware respects the already authenticated user"""
        token = JSONWebTokenBackend().create(self.other_user)

        request = HttpRequest()
        request.user = self.user
        request.META[HTTP_AUTHORIZATION_HEADER] = f"Token {token}"

        info = InfoObject(context=request)

        def next(root, info, **kwargs):
            self.assertTrue(hasattr(info.context, "user"))
            self.assertEqual(info.context.user, self.user)

        settings = {
            "AUTHENTICATION_BACKENDS": (
                "django_ariadne_jwt.backends.JSONWebTokenBackend",
                "django.contrib.auth.backends.ModelBackend",
            )
        }

        with self.settings(**settings):
            middleware = JSONWebTokenMiddleware()
            middleware.resolve(next, {}, info)

    def tests_regular_requests(self):
        # fmt: off
        """Tests that the middleware is being called correctly on """ \
            """regular requests"""
        # fmt: on

        type_definitions = ariadne.gql(
            """
            type Query {
                test: String!
            }
        """
        )

        query_type = ariadne.QueryType()

        def resolve_test(_, info):
            request = info.context
            self.assertTrue(hasattr(request, "user"))
            self.assertEqual(request.user, self.user)

            return "Test!"

        resolve_test = Mock(wraps=resolve_test)
        query_type.set_field("test", resolve_test)

        schema = ariadne.make_executable_schema(
            [type_definitions], [query_type]
        )

        middleware = JSONWebTokenMiddleware()

        token = JSONWebTokenBackend().create(self.user)

        request = HttpRequest()
        request.META[HTTP_AUTHORIZATION_HEADER] = f"Token {token}"

        settings = {
            "AUTHENTICATION_BACKENDS": (
                "django_ariadne_jwt.backends.JSONWebTokenBackend",
                "django.contrib.auth.backends.ModelBackend",
            )
        }

        with self.settings(**settings):
            # Spies on the JSONWebTokenMiddleware.resolve method
            def spy(*args, **kwargs):
                return JSONWebTokenMiddleware.resolve(
                    middleware, *args, **kwargs
                )

            spy = Mock(wraps=spy)

            with patch.object(middleware, "resolve", new=spy):
                ariadne.graphql_sync(
                    schema,
                    {
                        "query": """
                        query {
                            test
                        }
                        """
                    },
                    context_value=request,
                    middleware=[middleware],
                )

                self.assertTrue(spy.called)
                self.assertTrue(resolve_test.called)
