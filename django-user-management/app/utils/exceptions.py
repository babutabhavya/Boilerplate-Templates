class BaseException(Exception):
    def __init__(self, message=None) -> None:
        self.message = message


class BadRequestException(BaseException):
    pass


class NotFoundException(BaseException):
    pass


class ForbiddenException(BaseException):
    pass
