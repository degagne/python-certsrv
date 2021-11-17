import re
import os
import requests

from contextlib import suppress
from typing import NoReturn, Union
from requests.auth import HTTPBasicAuth
from requests_ntlm3 import HttpNtlmAuth
from certsrv.utils import handle_response, find_error_response, retrieve_cert
from certsrv import DEFAULT_CA_FILE, USER_AGENT, PKI_HEADER, PKCS7_HEADER
from certsrv.errors import RequestDeniedError, CertificatePendingError


class Certsrv:
    """
    Microsoft Active Directory Certificate Services.

    This class provides an interface into the Certification Authority
    Web Enrollment service, to create and retrieve certificates from
    the Active Directory Certificate Servers (ADCS).

    :param server: The FQDN of the Active Directory Certificate Service server.
    :param username: The username for authentication
    :param password: The password for authentication
    :param auth_method: The authentication method. Either 'basic' or 'ntlm'. 
        Defaults to 'basic'.
    :param cafile: A PEM file containing the CA certificates. Defaults to a 
        filesystem path defined by the OpenSSL library.
    """

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        auth_method: str = "basic",
        cafile: str = None
    ) -> NoReturn:
        """ class constructor """

        self.server = server
        self.auth_method = auth_method

        self.session = requests.Session()
        self.session.auth = self._set_credentials(username, password)
        self.session.verify = cafile or DEFAULT_CA_FILE
        self.session.headers = {"User-Agent": USER_AGENT}

    def _set_credentials(
        self,
        username: str,
        password: str
    ) -> Union[HttpNtlmAuth, HTTPBasicAuth]:
        """ set credentials for ADCS authentication """
        return HttpNtlmAuth(username, password, send_cbt=True) \
            if self.auth_method == "ntlm" \
                else HTTPBasicAuth(username, password)

    @handle_response(expected_status_codes={200})
    def _get(self, path: str, **kwargs: dict) -> requests.Response:
        """ submit a get request to the ADCS server """
        return self.session.get(os.path.join(self.server, path), **kwargs)

    @handle_response(expected_status_codes={200, 201, 204})
    def _post(self, path: str, **kwargs: dict) -> requests.Response:
        """ submit a post request to the ADCS server """
        return self.session.post(os.path.join(self.server, path), **kwargs)

    def get_cert(self, csr: bytes, template: str, encoding="b64") -> str:
        """
        Requests a certificate from the ADCS server.

        :param csr: The certificate signing request (CSR) to submit.
        :param template: The certificate template the certificate should 
            be issued from.
        :param encoding: The desired encoding for the returned certificate.
        :return: The issued certificate.
        :raise CertificatePendingError: The request needs to be approved by 
            the CA admin.
        :raise RequestDeniedError: The request was denied by the ADCS server.
        """
        response = self._post("certsrv/certfnsh.asp", data={
            "Mode": "newreq",
            "CertRequest": csr,
            "CertAttrib": f"CertificateTemplate:{template}",
            "FriendlyType": "Saved-Request Certificate",
            "TargetStoreFlags": "0",
            "SaveCert": "yes"
        })

        try:
            req_id = re.search(r'certnew.cer\?ReqID\=([0-9]+)', response.text).group(1)
        except AttributeError:
            if re.search(f"Certificate Pending", response.text):
                with suppress(AttributeError):
                    req_id = re.search(
                        f"Your Request Id is ([0-9]+).", response.text).group(1)
                    raise CertificatePendingError(req_id)

            raise RequestDeniedError(find_error_response(response.text))

        return self.get_existing_cert(req_id, encoding)

    @retrieve_cert(PKI_HEADER)
    def get_existing_cert(self, req_id: int, encoding: str = "b64") -> str:
        """
        Get an already created certificate from the ADCS server.

        :param req_id: The request ID to retrieve.
        :param encoding: The desired encoding for the returned certificate.
        :return: The issued certificate.
        :raise CertificateRetrievalError: If the certificate cannot be 
            retrieved.
        """
        return self._get("certsrv/certnew.cer", params={
            "ReqID": req_id,
            "Enc": encoding
        })

    @retrieve_cert(PKI_HEADER)
    def get_ca_cert(self, encoding: str = "b64") -> str:
        """
        Get the latest CA certificate from the ADCS server.

        :param encoding: The desired encoding for the returned certificate.
        :return: The latest CA certificate.
        :raise CertificateRetrievalError: If the certificate cannot be 
            retrieved.
        """
        return self._get("certsrv/certnew.cer", params={
            "ReqID": "CACert",
            "Enc": encoding,
            "Renewal": -1 # targets the latest certificate
        })

    @retrieve_cert(PKCS7_HEADER)
    def get_ca_chain(self, encoding="b64") -> str:
        """
        Get the CA chain from the ADCS server.

        :param encoding: The desired encoding for the returned certificate.
        :return: The CA chain in PKCS#7 format.
        :raise CertificateRetrievalError: If the certificate cannot be 
            retrieved.
        """
        return self._get("certsrv/certnew.p7b", params={
            "ReqID": "CACert",
            "Enc": encoding,
            "Renewal": -1 # targets the latest certificate
        })
