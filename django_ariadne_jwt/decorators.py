"""GraphQL decorators module"""
from django.http import HttpRequest
from .exceptions import LoginRequiredError


def login_required(resolver):
    """Requires login for a resolver"""

    def wrapper(parent, info, *args, **kwargs):
        if isinstance(info.context, HttpRequest):
            user = getattr(info.context, "user", None)

            if user is not None and user.is_authenticated:
                resolved = resolver(parent, info, *args, **kwargs)

            else:
                raise LoginRequiredError()

        return resolved

    return wrapper
