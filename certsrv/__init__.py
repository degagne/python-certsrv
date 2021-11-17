import ssl


verify_paths = ssl.get_default_verify_paths()

DEFAULT_CA_FILE = verify_paths.cafile or verify_paths.capath
USER_AGENT      = "Mozilla/5.0 (Windows NT 6.1; rv:77.0) Gecko/20190101 Firefox/77.0"
PKI_HEADER      = "application/pkix-cert"
PKCS7_HEADER    = "application/x-pkcs7-certificates"

from .certsrv import Certsrv
from .errors import RequestError
from .errors import RequestDeniedError
from .errors import CertificateRetrievalError
from .errors import CertificatePendingError
