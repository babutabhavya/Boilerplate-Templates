from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.response import Response
from utils.exceptions import BadRequestException, NotFoundException


from utils.exceptions import ForbiddenException  # isort: skip


def api_exception_handling(
    function,
):
    """
    Decorator to catch generic exceptions
    """

    def wrapper(*args, **kwargs):
        msg = "Internal Server Error"
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        try:
            return function(*args, **kwargs)
        except NotFoundException as error:
            # logger.error("NotFoundException", error=error)
            msg = error.message
            status_code = status.HTTP_404_NOT_FOUND
        except BadRequestException as error:
            # logger.error("BadRequestException", error=error)
            msg = error.message
            status_code = status.HTTP_400_BAD_REQUEST
        except ForbiddenException as error:
            msg = (
                getattr(error, "message")
                or "You are not allowed to access this resource"
            )
            print("ForbiddenException", error)
            status_code = status.HTTP_403_FORBIDDEN
        except AuthenticationFailed as error:
            print("Authentication Failed", error)
            raise error from error
        except ValidationError as error:
            raise error
        except Exception as error:  # pylint: disable=W0703
            print("ForbiddenException", error)
        return Response({"error": msg}, status=status_code)

    return wrapper
