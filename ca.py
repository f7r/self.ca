from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta


class CASigner():
    """
    use a private key and a CertificateBuilder instance to sign new cert.
    """

    def __init__(self, private_key, issuer):
        self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.issuer = issuer

    def sign(self, csr, valid_days):
        today = datetime.today()
        start_time = datetime(today.year, today.month, today.day)
        end_time = start_time + timedelta(valid_days)
        attr = {
            "issuer_name": self.issuer,
            "subject_name": csr.subject,
            "public_key": csr.public_key(),
            "serial_number": x509.random_serial_number(),
            "not_valid_before": start_time,
            "not_valid_after": end_time,
            "extensions": csr.extensions,
        }
        cert_builder = x509.CertificateBuilder(**attr)
        return cert_builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
