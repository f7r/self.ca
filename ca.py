from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.extensions import Extension
from datetime import datetime, timedelta


class CABuilder(object):

    def __init__(self, subject_name, extensions={}, valid_days=365*3):
        self.subject_name = subject_name
        self.valid_days = valid_days
        self.issuer_name = self.subject_name
        self.default_extensions.update(extensions)
        self.extensions = self.default_extensions.values()
        self.attr = self.get_attr()

    def get_attr(self):
        today = datetime.today()
        start_time = datetime(today.year, today.month, today.day)
        end_time = start_time + timedelta(self.valid_days)
        attr = {
                "issuer_name": self.issuer_name,
                "subject_name": self.subject_name,
                "public_key": self.public_key,
                "serial_number": self.serial_number,
                "not_valid_before": start_time,
                "not_valid_after": end_time,
                "extensions": self.extensions,
        }
        return attr

    def build_ca(self):
        self.builder = x509.CertificateBuilder(**self.attr)
        self.cert = self.builder.sign(
                private_key=self.private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
        )
        return CAPack(self.private_key, self.cert)

    # Class default attribute.
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
    )
    public_key = private_key.public_key()
    serial_number = x509.random_serial_number()

    default_keyusage = {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": True,
            "crl_sign": True,
            "encipher_only": False,
            "decipher_only": False,
    }

    default_extensions = {
            "keyUsage": Extension(
                    ExtensionOID.KEY_USAGE,
                    True,
                    x509.KeyUsage(**default_keyusage),
            ),
            "basicConstraints": Extension(
                    ExtensionOID.BASIC_CONSTRAINTS,
                    True,
                    x509.BasicConstraints(ca=True, path_length=None),
            ),
            "subjectKeyIdentifier": Extension(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                    False,
                    x509.SubjectKeyIdentifier.from_public_key(public_key),
            ),
            "authorityKeyIdentifier": Extension(
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                    False,
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                            public_key
                    ),
            ),
    }


class CAPack(object):
    # Include CA's private_key and ROOT cert.

    def __init__(self, private_key, cert):
        self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.cert = cert

    @classmethod
    def load_from_file(cls, private_key_file, password, cert_file):
        with open(private_key_file, "rb") as f:
            private_key_data = f.read()
            private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password,
                    default_backend(),
            )
        with open(cert_file, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(
                    cert_data,
                    default_backend(),
            )
        return cls(private_key, cert)

    def sign(self, csr, valid_days):
        today = datetime.today()
        start_time = datetime(today.year, today.month, today.day)
        end_time = start_time + timedelta(valid_days)
        attr = {
                "issuer_name": self.cert.subject,
                "subject_name": csr.subject,
                "public_key": csr.public_key(),
                "serial_number": x509.random_serial_number(),
                "not_valid_before": start_time,
                "not_valid_after": end_time,
                "extensions": csr.extensions,
        }
        builder = x509.CertificateBuilder(**attr)
        return builder.sign(
                private_key=self.private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
        )
