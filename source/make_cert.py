#! /usr/bin/python3
"""
Use to create a CA and cert.
"""
import configparser
import utils
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ca import CASigner
from csr import CSRBuilder
from cryptography.hazmat.primitives.asymmetric import rsa


def read_ca(ca_key_file, ca_cert_file):
    password = None
    with open(ca_key_file, "rb") as f:
        ca_key_data = f.read()
        ca_key = serialization.load_pem_private_key(
            ca_key_data,
            password,
            default_backend(),
        )
    with open(ca_cert_file, "rb") as f:
        ca_cert_data = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            ca_cert_data,
            default_backend(),
        )
    return ca_key, ca_cert


def make_csr(private_key, cert_attr):
    cert_subject_name = utils.get_subject_name(cert_attr)
    csr_builder = CSRBuilder(private_key, cert_subject_name)
    csr = csr_builder.build_csr()
    return csr


def main():
    config = configparser.SafeConfigParser()
    source_dir = utils.get_source_dir()
    config_file = "{0}/config.ini".format(source_dir)
    config.read(config_file)
    cert_attr = {}
    for key in utils.ATTR_ABBR:
        try:
            value = config.get('Cert', key)
        except configparser.NoOptionError:
            value = config.get('Cert', utils.ATTR_ABBR[key])
        if value:
            cert_attr[key] = value
    valid_days = config.getint('Cert', 'valid_days')
    ca_key_file = config.get('CA', 'ca_key')
    ca_cert_file = config.get('CA', 'ca_cert')
    key_file = config.get('Cert', 'key_file')
    cert_file = config.get('Cert', 'cert_file')

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    csr = make_csr(private_key, cert_attr)
    ca_key, ca_cert = read_ca(ca_key_file, ca_cert_file)
    signer = CASigner(ca_key, ca_cert.subject)
    cert = signer.sign(csr, valid_days)
    utils.wirte_file(private_key, cert, key_file, cert_file)


if __name__ == "__main__":
    main()
