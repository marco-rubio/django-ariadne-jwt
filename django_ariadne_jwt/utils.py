"""ariadne_django_jwt_auth utils module"""
import datetime
import jwt
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from jwt.exceptions import DecodeError, ExpiredSignatureError
from .exceptions import (
    AuthenticatedUserRequiredError,
    ExpiredTokenError,
    MaximumTokenLifeReachedError,
    InvalidTokenError,
)

ORIGINAL_IAT_CLAIM = "orig_iat"
HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"
AUTHORIZATION_HEADER_PREFIX = "Token"


def get_token_from_http_header(request):
    """Retrieves the http authorization header from the request"""
    token = None

    try:
        header = request.META.get(HTTP_AUTHORIZATION_HEADER, "")

    except AttributeError:
        header = ""

    try:
        prefix, payload = header.split()

    except ValueError:
        prefix = "-"

    if prefix.lower() == AUTHORIZATION_HEADER_PREFIX.lower():
        token = payload

    return token


def has_reached_end_of_life(oldest_iat_claim):
    """Checks if the token has reached its end of life"""
    expiration_delta = getattr(
        settings, "JWT_REFRESH_EXPIRATION_DELTA", datetime.timedelta(days=7)
    )

    now = timezone.localtime()
    original_issue_time = timezone.make_aware(
        datetime.datetime.fromtimestamp(int(oldest_iat_claim))
    )

    end_of_life = original_issue_time + expiration_delta

    return now > end_of_life


def create_jwt(user, extra_payload={}):
    """Creates a JWT for an authenticated user"""
    if not user.is_authenticated:
        raise AuthenticatedUserRequiredError(
            "JWT generationr requires an authenticated user"
        )

    expiration_delta = getattr(
        settings, "JWT_EXPIRATION_DELTA", datetime.timedelta(minutes=5)
    )

    now = timezone.localtime()

    payload = {
        **extra_payload,
        "user": user.username,
        "iat": int(now.timestamp()),
        "exp": int((now + expiration_delta).timestamp()),
    }

    return jwt.encode(payload, settings.SECRET_KEY).decode("utf-8")


def refresh_jwt(token):
    """Refreshes a JWT if possible"""
    decoded = decode_jwt(token)

    oldest_iat_claim = decoded.get(ORIGINAL_IAT_CLAIM, decoded.get("iat"))

    if has_reached_end_of_life(oldest_iat_claim):
        raise MaximumTokenLifeReachedError()

    User = get_user_model()

    credentials = {User.USERNAME_FIELD: decoded["user"]}

    try:
        user = User.objects.get(**credentials)

    except User.DoesNotExist:
        raise InvalidTokenError(_("User not found"))

    return create_jwt(user, {ORIGINAL_IAT_CLAIM: decoded["iat"]})


def decode_jwt(token):
    """Decodes a JWT"""
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY)

    except ExpiredSignatureError:
        raise ExpiredTokenError()

    except DecodeError:
        raise InvalidTokenError()

    return decoded
