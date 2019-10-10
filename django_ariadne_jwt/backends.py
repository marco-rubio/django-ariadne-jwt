"""GraphQL auth backends module"""
from django.contrib.auth import get_user_model
from django.conf import settings
from .exceptions import JSONWebTokenError
from .utils import decode_jwt


class JSONWebTokenBackend(object):
    """Authenticates against a JSON Web Token"""

    def authenticate(self, request, token=None, **kwargs):
        """Performs authentication"""
        if token is None:
            return

        try:
            token_data = decode_jwt(token)

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
