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


def resolve_token_auth(parent, info, **credentials):
    """Resolves the token auth mutation"""
    user = authenticate(info.context, **credentials)
    return {"token": load_backend().create(user) if user else None}


def resolve_refresh_token(parent, info, token):
    """Resolves the resfresh token mutaiton"""

    try:
        token = load_backend().refresh(token)

    except (InvalidTokenError, MaximumTokenLifeReachedError):
        token = None

    return {"token": token}


def resolve_verify_token(parent, info, token: str):
    """Resolves the verify token mutation"""
    token_verification = {}

    try:
        decoded = load_backend().decode(token)
        token_verification["valid"] = True
        token_verification["user"] = decoded.get("user")

    except (InvalidTokenError, ExpiredTokenError):
        token_verification["valid"] = False

    return token_verification
