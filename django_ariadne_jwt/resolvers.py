"""ariadne_django_jwt resolvers module"""
from ariadne import gql
from django.contrib.auth import authenticate
from .exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    MaximumTokenLifeReachedError,
)
from .utils import create_jwt, decode_jwt, refresh_jwt


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
    token = None
    user = authenticate(info.context, **credentials)

    if user is not None:
        token = create_jwt(user)

    return {"token": token}


def resolve_refresh_token(parent, info, token):
    """Resolves the resfresh token mutaiton"""

    try:
        token = refresh_jwt(token)

    except (InvalidTokenError, MaximumTokenLifeReachedError):
        token = None

    return {"token": token}


def resolve_verify_token(parent, info, token: str):
    """Resolves the verify token mutation"""
    token_verification = {}

    try:
        decoded = decode_jwt(token)
        token_verification["valid"] = True
        token_verification["user"] = decoded.get("user")

    except (InvalidTokenError, ExpiredTokenError):
        token_verification["valid"] = False

    return token_verification
