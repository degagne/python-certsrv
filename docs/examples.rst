Examples
========

Generate certificate from certificate signing request (CSR) file.

.. code-block:: python
    :caption: Python
    :linenos:

    from pathlib import Path
    from certsrv import Certsrv


    csr = Path("/path/to/csr/file.csr").read_bytes()
    template = "CertTemplate"

    ca = Certsrv("someserver.com", "jsmith", "securepassword!", "ntlm")
    cert = ca.get_cert(csr, template)