import unittest

from datetime import datetime, timedelta
from lxml.builder import E
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, serialization

import pankkiyhteys
import utils

class KeyTestSuite(unittest.TestCase):
    def sign_cert(self, key, *,
                  not_valid_before=datetime.utcnow(),
                  duration=timedelta(days=1)):
        """
        Helper function to create self signed certificate

        Returns:
            cryptography.x509.Certificate:
        """
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'FI'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'My Company'),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, '1234567890'),
        ])

        return (x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(key._private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(not_valid_before)
                    .not_valid_after(not_valid_before + duration)
                    .sign(key._private_key, pankkiyhteys.key.HASH_FUNCTION(),
                          default_backend()))

    def test_key(self):
        # Try invalid key type
        with self.assertRaises(ValueError):
            private_key = asymmetric.dsa.generate_private_key(
                key_size=1024,
                backend=default_backend()
            )
            pankkiyhteys.Key(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Try invalid key size
        with self.assertRaises(ValueError):
            private_key = asymmetric.rsa.generate_private_key(
                key_size=1024,
                public_exponent=65537,
                backend=default_backend()
            )
            pankkiyhteys.Key(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Generate new key
        key = pankkiyhteys.Key.generate()
        private_key = key.private_key()
        assert isinstance(key, pankkiyhteys.Key)
        assert not key.valid()  # <- No certificate

        # Export encrypted private and try to load it
        protected_private_key = key.private_key(b'mypassword')
        key = pankkiyhteys.Key(protected_private_key, password=b'mypassword')
        assert isinstance(key, pankkiyhteys.Key)

        # Try to load private key with incorrect password
        with self.assertRaises(ValueError):
            key = pankkiyhteys.Key(protected_private_key, password=b'notmypassword')

    def test_sign(self):
        """
        Test if signxml works
        """

        key = utils.create_test_key()
        root = key.sign(E.root(E.content('Hello, world!')))

        # Validate ApplicationRequest schema
        with open('tests/xsd/xmldsig-core-schema.xsd') as xsd:
            schema = etree.XMLSchema(etree.parse(xsd))

        # Last element should be signature
        schema.assertValid(root[-1])

    def test_certificate(self):
        # Generate new key
        key = pankkiyhteys.Key.generate()
        private_key = key.private_key()
        assert isinstance(key, pankkiyhteys.Key)
        assert not key.valid()  # <- No certificate

        # Try to export certificate
        with self.assertRaises(AttributeError):
            cert = key.certificate()

        # Try to check valid duration
        with self.assertRaises(AttributeError):
            cert = key.valid_duration

        # Try to load private key and self signed certificate
        cert = self.sign_cert(key, duration=timedelta(days=1))
        key = pankkiyhteys.Key(private_key, cert)
        assert isinstance(key, pankkiyhteys.Key)
        assert key.valid()
        assert timedelta(hours=23) < key.valid_duration <= timedelta(days=1)

        # Export certificate and try to load it
        cert = key.certificate()
        key = pankkiyhteys.Key(private_key, cert)
        assert isinstance(key, pankkiyhteys.Key)
        assert key.valid()
