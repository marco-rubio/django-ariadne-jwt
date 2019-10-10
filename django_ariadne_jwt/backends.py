"""GraphQL auth backends module"""
import datetime
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django.utils.translation import ugettext_lazy as _
import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError

from .exceptions import (
    AuthenticatedUserRequiredError,
    ExpiredTokenError,
    InvalidTokenError,
    JSONWebTokenError,
    MaximumTokenLifeReachedError,
)


def load_backend():
    return import_string(
        getattr(
            settings,
            "JWT_BACKEND",
            "django_ariadne_jwt.backends.JSONWebTokenBackend",
        )
    )()


class JSONWebTokenBackend(object):
    """Authenticates against a JSON Web Token"""

    DEFAULT_JWT_ALGORITHM = "HS256"
    ORIGINAL_IAT_CLAIM = "orig_iat"
    HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"
    AUTHORIZATION_HEADER_PREFIX = "Token"
    DEFAULT_JWT_ALGORITHM = "HS256"

    def get_token_from_http_header(self, request):
        """Retrieves the http authorization header from the request"""
        header = request.META.get(self.HTTP_AUTHORIZATION_HEADER, False)
        if header is False:
            return None

        prefix, token = header.split()
        if prefix.lower() != self.AUTHORIZATION_HEADER_PREFIX.lower():
            return None

        return token

    def authenticate(self, request, token=None, **kwargs):
        """Performs authentication"""
        if token is None:
            return

        try:
            token_data = self.decode(token)

        except JSONWebTokenError:
            return

        return self.get_user(**self.get_user_kwargs(token_data))

    def get_user(self, user_id=None, **kwargs):
        """Gets a user from its id"""
        User = get_user_model()
        if user_id is not None:
            kwargs["pk"] = user_id

        try:
            return User.objects.get(**kwargs)

        except User.DoesNotExist:
            return None

    def get_user_kwargs(self, token_data):
        User = get_user_model()
        return {User.USERNAME_FIELD: token_data["user"]}

    def create(self, user, extra_payload={}):
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

        return jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=getattr(
                settings, "JWT_ALGORITHM", self.DEFAULT_JWT_ALGORITHM
            ),
        ).decode("utf-8")

    def refresh(self, token):
        """Refreshes a JWT if possible"""
        decoded = self.decode(token)

        oldest_iat_claim = decoded.get(
            self.ORIGINAL_IAT_CLAIM, decoded.get("iat")
        )

        if self.has_reached_end_of_life(oldest_iat_claim):
            raise MaximumTokenLifeReachedError()

        User = get_user_model()

        credentials = {User.USERNAME_FIELD: decoded["user"]}

        try:
            user = User.objects.get(**credentials)

        except User.DoesNotExist:
            raise InvalidTokenError(_("User not found"))

        return self.create(user, {self.ORIGINAL_IAT_CLAIM: decoded["iat"]})

    def decode(self, token):
        """Decodes a JWT"""
        try:
            decoded = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=getattr(
                    settings, "JWT_ALGORITHMS", self.DEFAULT_JWT_ALGORITHM
                ),
            )

        except ExpiredSignatureError:
            raise ExpiredTokenError()

        except DecodeError:
            raise InvalidTokenError()

        return decoded

    def has_reached_end_of_life(self, oldest_iat_claim):
        """Checks if the token has reached its end of life"""
        expiration_delta = getattr(
            settings,
            "JWT_REFRESH_EXPIRATION_DELTA",
            datetime.timedelta(days=7),
        )

        now = timezone.localtime()
        original_issue_time = timezone.make_aware(
            datetime.datetime.fromtimestamp(int(oldest_iat_claim))
        )

        end_of_life = original_issue_time + expiration_delta

        return now > end_of_life
