"""django_ariadne_jwt_auth decorators tests"""
import ariadne
from dataclasses import dataclass
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import TestCase
from unittest.mock import Mock
from django_ariadne_jwt.backends import JSONWebTokenBackend
from django_ariadne_jwt.decorators import login_required
from django_ariadne_jwt.middleware import JSONWebTokenMiddleware


HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"


@dataclass
class InfoObject(object):
    context: HttpRequest


class DecoratorsTestCase(TestCase):
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

    def test_login_required_decorator_with_valid_token(self):
        """Tests the login required decorator called with valid token"""
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
        decorated_resolve_test = Mock(wraps=login_required(resolve_test))
        query_type.set_field("test", decorated_resolve_test)

        schema = ariadne.make_executable_schema(
            [type_definitions], [query_type]
        )

        middleware = [JSONWebTokenMiddleware()]

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
                middleware=middleware,
            )

            self.assertTrue(resolve_test.called)

    def test_login_required_decorator_without_valid_token(self):
        """Tests the login required decorator called without valid token"""
        type_definitions = ariadne.gql(
            """
            type Query {
                me: String!
                mustfail: String!
            }
        """
        )

        query_type = ariadne.QueryType()

        resolve_me = Mock(return_value="Me!")
        query_type.set_field("me", resolve_me)

        resolve_mustfail = Mock(return_value="FAIL!")
        decorated_resolve_mustfail = Mock(
            wraps=login_required(resolve_mustfail)
        )
        query_type.set_field("mustfail", decorated_resolve_mustfail)

        schema = ariadne.make_executable_schema(
            [type_definitions], [query_type]
        )

        middleware = [JSONWebTokenMiddleware()]

        request = HttpRequest()

        settings = {
            "AUTHENTICATION_BACKENDS": (
                "django_ariadne_jwt.backends.JSONWebTokenBackend",
                "django.contrib.auth.backends.ModelBackend",
            )
        }

        with self.settings(**settings):
            success, result = ariadne.graphql_sync(
                schema,
                {
                    "query": """
                    query {
                        me
                        mustfail
                    }
                    """
                },
                context_value=request,
                middleware=middleware,
            )

            self.assertTrue(resolve_me.called)
            self.assertFalse(resolve_mustfail.called)

            self.assertIsNotNone(result)
            self.assertIn("errors", result)

            test_field_error_found = False

            for error_data in result["errors"]:
                if "mustfail" in error_data["path"]:
                    test_field_error_found = True

            self.assertTrue(test_field_error_found)
