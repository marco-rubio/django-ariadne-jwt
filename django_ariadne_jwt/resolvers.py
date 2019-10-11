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


class BaseTokenResolver:
    def get_token(self):
        raise NotImplementedError()

    def get_payload(self):
        return {"token": self.get_token()}


class TokenAuthResolver(BaseTokenResolver):
    def get_token(self):
        return load_backend().create(self.user) if self.user else None

    def __call__(self, parent, info, **credentials):
        self.user = authenticate(info.context, **credentials)
        return self.get_payload()


# TODO Add DeprecationWarning?
resolve_token_auth = TokenAuthResolver()


class RefreshTokenResolver(BaseTokenResolver):
    def get_token(self):
        try:
            return load_backend().refresh(self.token)
        except (InvalidTokenError, MaximumTokenLifeReachedError):
            pass

    def __call__(self, parent, info, token):
        """Resolves the resfresh token mutaiton"""
        self.token = token
        return self.get_payload()


resolve_refresh_token = RefreshTokenResolver()


class VerifyTokenResolver:
    def get_payload(self):
        try:
            decoded = load_backend().decode(self.token)
            return {"valid": True, "user": decoded.get("user")}
        except (InvalidTokenError, ExpiredTokenError):
            return {"valid": False}

    def __call__(self, parent, info, token: str):
        """Resolves the verify token mutation"""
        self.token = token
        return self.get_payload()


resolve_verify_token = VerifyTokenResolver()
