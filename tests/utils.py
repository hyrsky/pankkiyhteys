import pankkiyhteys

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric

def create_test_key(create_cert=True, *,
                    not_valid_before=datetime.utcnow(),
                    duration=timedelta(days=1)):
    private_key = asymmetric.rsa.generate_private_key(
        key_size=2048,
        public_exponent=65537,
        backend=default_backend()
    )

    cert = None
    if create_cert:
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'FI'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'My Company'),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, '1234567890'),
        ])

        cert = (x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(not_valid_before)
                    .not_valid_after(not_valid_before + duration)
                    .sign(private_key, pankkiyhteys.key.HASH_FUNCTION(),
                          default_backend()))

    return pankkiyhteys.Key(private_key, cert)
