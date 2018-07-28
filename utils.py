from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

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

def get_extensions(names):
    pass
