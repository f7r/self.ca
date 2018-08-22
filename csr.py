from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class CSRBuilder(object):

    def __init__(self, subject_name, extensions=[]):
        self.subject_name = subject_name
        self.extensions = extensions

    def build_csr(self):
        self.builder = x509.CertificateSigningRequestBuilder(
            self.subject_name,
            self.extensions,
        )
        self.csr = self.builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        return CSRPack(self.private_key, self.csr)

    # Class default attribute.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


class CSRPack(object):
    # Include CSR's private_key and CSR itself.

    def __init__(self, private_key, csr):
        self.private_key = private_key
        self.csr = csr

    @classmethod
    def load_from_file(cls, private_key_file, password, csr_file):
        with open(private_key_file, "rb") as f:
            private_key_data = f.read()
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password,
                default_backend(),
            )
        with open(csr_file, "rb") as f:
            csr_data = f.read()
            csr = x509.load_pem_x509_csr(
                csr_data,
                default_backend(),
            )
        return cls(private_key, csr)
