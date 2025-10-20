class ApplicationNotFoundException(Exception):
    pass

class NotFoundException(Exception):
    pass

class InvalidDataException(Exception):
    pass

class DatabaseUpdateException(Exception):
    pass

class SafeNotFoundException(Exception):
    pass

class TokenDecodeError(Exception):
    """Exception raised for errors during token decoding."""
    pass

class TokenExpiredError(Exception):
    """Exception raised when the token has expired."""
    pass

class TokenInvalidError(Exception):
    """Exception raised when the token is invalid."""
    pass

class NameAlreadyExist(Exception):
    pass

class UserAlreadyExist(Exception):
    pass

class LoginFailed(Exception):
    pass

class ErrorOccurred(Exception):
    pass

class SomethingWentWrong(Exception):
    pass

class KeyMissing(Exception):
    pass

class ThirdPartyAccountNotExist(Exception):
    pass

class InsufficientRight(Exception):
    pass

class AttemptsExceeded(Exception):
    pass

class CustomException(Exception):
    pass
