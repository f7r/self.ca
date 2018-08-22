from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.extensions import Extension


ATTR_NAMES = {
    "commonName": NameOID.COMMON_NAME,
    "CN": NameOID.COMMON_NAME,
    "countryName": NameOID.COUNTRY_NAME,
    "C": NameOID.COUNTRY_NAME,
    "localityName": NameOID.LOCALITY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "organizationName": NameOID.ORGANIZATION_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "organizationalUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
    "E": NameOID.EMAIL_ADDRESS,
}


def get_subject_name(names):
    subject = []
    for k in names:
        if k in ATTR_NAMES:
            name_attr = x509.NameAttribute(ATTR_NAMES[k], names[k])
            subject.append(name_attr)
    subject_name = x509.Name(subject)
    return subject_name


# Extensions
def get_extension_keyusage(ext_attr):
    all_keyusage = [
        "digital_signature", "content_commitment", "key_encipherment",
        "data_encipherment", "key_agreement", "key_cert_sign",
        "crl_sign", "encipher_only", "decipher_only",
    ]
    keyusage = {}
    for k in all_keyusage:
        if k in ext_attr:
            keyusage[k] = True
        else:
            keyusage[k] = False
    return Extension(ExtensionOID.KEY_USAGE, True, x509.KeyUsage(**keyusage))


EXTENSION_NAMES = {
    "keyUsage": get_extension_keyusage,
}


def get_extensions(ext_names):
    extensions = {}
    for ext in ext_names:
        if ext in EXTENSION_NAMES:
            func = EXTENSION_NAMES[ext]
            extension = func(ext_names[ext])
            extensions[ext] = extension
    return extensions
