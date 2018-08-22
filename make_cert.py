#! /usr/bin/python3
"""
Use to create a CA and cert.
"""
from cryptography.hazmat.primitives import serialization
from ca import CABuilder
from csr import CSRBuilder
from utils import get_subject_name


def main():
    """main function."""

    ca_attr = {
        "commonName": "self.ca",
        "countryName": "CN",
        "E": "zmj@falseuser.cn"
    }
    ca_subject_name = get_subject_name(ca_attr)
    ca_builder = CABuilder(ca_subject_name, valid_days=365)
    ca_pack = ca_builder.build_ca()

    with open("CA.key", "wb") as f:
        f.write(
            ca_pack.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open("CA.pem", "wb") as f:
        f.write(ca_pack.cert.public_bytes(serialization.Encoding.PEM))
    # c1 = CA.load_from_file("CA.key", None, "CA.pem")

    cert_attr = {
        "CN": "api.falseuser.cn",
        "C": "CN",
        "E": "zmj@falseuser.cn",
    }
    cert_subject_name = get_subject_name(cert_attr)
    csr_builder = CSRBuilder(cert_subject_name)
    csr_pack = csr_builder.build_csr()
    with open("csr.key", "wb") as f:
        f.write(
            csr_pack.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )
    cert = ca_pack.sign(csr_pack.csr, 365)
    with open("cert.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
