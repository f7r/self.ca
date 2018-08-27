#! /usr/bin/python3
"""
Use to create a CA and cert.
"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ca import CASigner
from csr import CSRBuilder
from utils import get_subject_name
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    cert_attr = {
        "CN": "api.falseuser.cn",
        "C": "CN",
        "E": "zmj@falseuser.cn",
    }
    cert_subject_name = get_subject_name(cert_attr)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    csr_builder = CSRBuilder(private_key, cert_subject_name)
    csr = csr_builder.build_csr()
    with open("private.key", "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )
    password = None
    with open("CA.key", "rb") as f:
        ca_key_data = f.read()
        ca_key = serialization.load_pem_private_key(
            ca_key_data,
            password,
            default_backend(),
        )
    with open("CA.pem", "rb") as f:
        ca_cert_data = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            ca_cert_data,
            default_backend(),
        )
    signer = CASigner(ca_key, ca_cert.subject)
    cert = signer.sign(csr, 365)
    with open("cert.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
