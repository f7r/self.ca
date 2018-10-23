import configparser
import utils
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.extensions import Extension
from ca import CASigner


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
    return private_key, cert


def main():
    config = configparser.SafeConfigParser()
    source_dir = utils.get_source_dir()
    config_file = "{0}/CA_CONFIG.ini".format(source_dir)
    config.read(config_file)
    ca_attr = {}
    for key in utils.ATTR_ABBR:
        try:
            value = config.get('CA', key)
        except configparser.NoOptionError:
            value = config.get('CA', utils.ATTR_ABBR[key])
        if value:
            ca_attr[key] = value
    valid_days = config.getint('CA', 'valid_days')
    ca_key_file = config.get('CA', 'ca_key')
    ca_cert_file = config.get('CA', 'ca_cert')
    ca_subject_name = utils.get_subject_name(ca_attr)
    key, cert = make_ca(ca_subject_name, valid_days)
    utils.wirte_file(key, cert, ca_key_file, ca_cert_file)


if __name__ == "__main__":
    main()
