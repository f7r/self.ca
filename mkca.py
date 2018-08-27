from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.extensions import Extension
from ca import CASigner
from utils import get_subject_name


def make_ca(subject_name, valid_days):
    """
    Create a CA root certificate.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
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
    extensions = [
        Extension(
            ExtensionOID.KEY_USAGE,
            True,
            x509.KeyUsage(**default_keyusage),
        ),
        Extension(
            ExtensionOID.BASIC_CONSTRAINTS,
            True,
            x509.BasicConstraints(ca=True, path_length=None),
        ),
        Extension(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            False,
            x509.SubjectKeyIdentifier.from_public_key(public_key),
        ),
        Extension(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            False,
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
        ),
    ]
    csr_builder = x509.CertificateSigningRequestBuilder(
        subject_name,
        extensions,
    )
    csr = csr_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )
    signer = CASigner(private_key, csr.subject)
    cert = signer.sign(csr, valid_days)
    with open("CA.key", "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open("CA.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    ca_attr = {
        "commonName": "self.ca",
        "countryName": "CN",
        "E": "zmj@falseuser.cn"
    }
    valid_days = 365*3
    ca_subject_name = get_subject_name(ca_attr)
    make_ca(ca_subject_name, valid_days)


if __name__ == "__main__":
    main()
