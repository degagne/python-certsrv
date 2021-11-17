from typing import NoReturn


class RequestError(Exception):
    """
    Exception raised for unexpected HTTP status codes. 
    """
    pass


class RequestDeniedError(Exception):
    """
    Exception raised when a certificate request is denied by the ADCS server.
    """
    pass


class CertificateRetrievalError(Exception):
    """
    Exception raised when a certificate wasn't retrieved from the ADCS server.
    """
    pass


class CertificatePendingError(Exception):
    """
    Exception raised when a certificate request requires approval.
    """

    def __init__(self, req_id: int) -> NoReturn:
        self.req_id = req_id

        super().__init__(self)

    def __str__(self):
        return (f"Your certificate request has been received, however, you "
                f"must wait for an administrator to issue the certificate "
                f"you requested. Your request Id is {self.req_id}.")