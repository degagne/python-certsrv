import re
import functools

from typing import Callable, Any
from contextlib import suppress
from certsrv.errors import RequestError, CertificateRetrievalError


def find_error_response(response: str) -> str:
    """
    Finds the error message in :class:`requests.Response` text object.
    
    :param response: :class:`requests.Response` object.
    :return: The retrieved error message, otherwise a generic message.
    """
    with suppress(AttributeError):
        return re.search(r'The disposition message is "([^"]+)', response).group(1)
    return "An unknown error occurred."


def handle_response(expected_status_codes: set):
    """
    Handler for :class:`requests.Response` object.

    :param expected_status_codes: A set of expected status codes.
    :return: :class:`requests.Response` object
    :raise RequestError: if the HTTP status code wasn't expected.
    """
    def wrap(func: Callable):
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            response = func(*args, **kwargs)
            # raise exceptions for 4xx or 5xx error codes
            response.raise_for_status()
            if response.status_code not in expected_status_codes:
                raise RequestError(
                    f"Unexpected HTTP status code {response.status_code} returned "
                    f"with reason {response.reason}.")
            return response
        return wrapper
    return wrap


def retrieve_cert(expected_header: str):
    """
    Retrieve certificate from :class:`request.Response` object.

    :param expected_header: The expected 'Content-Type' header for the 
        certificate request.
    :return: The issued certificate.
    :raise CertificateRetrievalError: If the certificate 'Content-Type' 
        header doesn't match the expected type.
    """
    def wrap(func: Callable):
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            response = func(*args, **kwargs)
            if response.headers["Content-Type"] != expected_header:
                # response doesn't contain a cert, raise error
                raise CertificateRetrievalError(find_error_response(response.text))
            with suppress(UnicodeDecodeError):
                # attempt to decode cert, otherwise return encoded cert
                return response.content.decode()
            return response.content
        return wrapper
    return wrap
