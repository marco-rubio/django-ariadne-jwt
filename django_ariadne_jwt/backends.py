"""GraphQL auth backends module"""
from django.contrib.auth import get_user_model
from .exceptions import JSONWebTokenError
from .utils import decode_jwt


class JSONWebTokenBackend(object):
    """Authenticates against a JSON Web Token"""

    def authenticate(self, request, token=None, **kwargs):
        """Performs authentication"""
        user = None

        if token is not None:
            token_data = None

            try:
                token_data = decode_jwt(token)

            except JSONWebTokenError:
                pass

            if token_data is not None:
                User = get_user_model()
                credentials = {User.USERNAME_FIELD: token_data["user"]}

                try:
                    user = User.objects.get(**credentials)

                except User.DoesNotExist:
                    pass

        return user

    def get_user(self, user_id):
        """Gets a user from its id"""
        User = get_user_model()

        try:
            return User.objects.get(pk=user_id)

        except User.DoesNotExist:
            return None
