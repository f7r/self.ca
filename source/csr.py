from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class CSRBuilder(object):

    def __init__(self, private_key, subject_name, extensions=[]):
        self.private_key = private_key
        self.subject_name = subject_name
        self.extensions = extensions

    def build_csr(self):
        self.builder = x509.CertificateSigningRequestBuilder(
            self.subject_name,
            self.extensions,
        )
        return self.builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
