"""ariadne_django_jwt resolvers module"""
from ariadne import gql
from django.contrib.auth import authenticate
from .backends import load_backend
from .exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    MaximumTokenLifeReachedError,
)

auth_token_definition = gql(
    """
    type AuthToken {
        token: String
    }
"""
)

auth_token_verification_definition = gql(
    """
    type AuthTokenVerification {
        valid: Boolean!
        username: String
    }
"""
)


class TokenAuthResolver:
    def get_payload(self, user):
        return {"token": load_backend().create(user) if user else None}

    def __call__(self, parent, info, **credentials):
        user = authenticate(info.context, **credentials)
        return self.get_payload(user)


# TODO Add DeprecationWarning?
resolve_token_auth = TokenAuthResolver()


class RefreshTokenResolver:
    def __call__(self, parent, info, token):
        """Resolves the resfresh token mutaiton"""

        try:
            token = load_backend().refresh(token)

        except (InvalidTokenError, MaximumTokenLifeReachedError):
            token = None

        return {"token": token}


resolve_refresh_token = RefreshTokenResolver()


class VerifyTokenResolver:
    def __call__(self, parent, info, token: str):
        """Resolves the verify token mutation"""
        token_verification = {}

        try:
            decoded = load_backend().decode(token)
            token_verification["valid"] = True
            token_verification["user"] = decoded.get("user")

        except (InvalidTokenError, ExpiredTokenError):
            token_verification["valid"] = False

        return token_verification


resolve_verify_token = VerifyTokenResolver()
