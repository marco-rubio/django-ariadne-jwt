"""ariadne_django exceptions module"""

from django.utils.translation import ugettext_lazy as _


class JSONWebTokenError(Exception):
    """Generic JSON Web Token error"""

    default_message = None

    def __init__(self, message=None):
        if message is None:
            message = self.default_message

        super().__init__(message)


class PermissionDenied(JSONWebTokenError):
    default_message = _("You do not have permission to perform this action")


class LoginRequiredError(JSONWebTokenError):
    """Error for cases when a login is required to access the data"""

    default_message = _("Login is required")


class ExpiredTokenError(JSONWebTokenError):
    default_message = _("Signature has expired")


class MaximumTokenLifeReachedError(JSONWebTokenError):
    """Error for cases when refreshed tokens hit their maximum life limit"""

    default_message = _("The maximum life for this token has been reached")


class AuthenticatedUserRequiredError(Exception):
    """Error for cases when an authenticated user is required"""


class InvalidTokenError(Exception):
    """Error for cases when the provided JWT is not valid"""

    default_message = _("The provided string is not a valid JWT")
