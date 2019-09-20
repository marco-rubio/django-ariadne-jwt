"""ariadne_django_jwt_auth middleware module"""
from django.contrib.auth import authenticate
from django.contrib.auth.models import AnonymousUser
from .utils import get_token_from_http_header

__all__ = ["JSONWebTokenMiddleware"]


class JSONWebTokenMiddleware(object):
    """Middleware to be used in conjuction with ariadne grapqh_* methods"""

    def resolve(self, next, root, info, **kwargs):
        """Performs the middleware relevant operations"""
        request = info.context

        token = get_token_from_http_header(request)

        if token is not None:
            user = getattr(request, "user", None)

            if user is None or isinstance(user, AnonymousUser):
                user = authenticate(request=request, token=token)

            if user is not None:
                setattr(request, "user", user)

        return next(root, info, **kwargs)
