import pankkiyhteys
import os

from datetime import datetime, timedelta

from lxml import etree
from lxml.builder import ElementMaker
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric


def assert_valid_schema(schema, element):
    filename = os.path.join(os.path.dirname(__file__), "xsd", schema)
    with open(filename) as f:
        xsd = etree.XMLSchema(etree.parse(f))

    xsd.assertValid(element)


def create_unsigned_application_request():
    E = ElementMaker(namespace="http://bxd.fi/xmldata/",
                     nsmap={None: "http://bxd.fi/xmldata/"})
    root = E.ApplicationRequest(
        E.CustomerId('1000000000'),
        E.Timestamp('2011-08-15T09:48:31.177+03:00'),
        E.Status('NEW'),
        E.Environment('TEST'),
        E.SoftwareId('soft'))

    return root


def generate_rsa_key(key_size=2048):
    private_key = asymmetric.rsa.generate_private_key(
        key_size=key_size, public_exponent=65537, backend=default_backend())

    return private_key


def create_test_key(*,
                    create_cert=True,
                    not_valid_before=datetime.utcnow(),
                    duration=timedelta(days=1)):
    private_key = generate_rsa_key()

    if create_cert:
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'FI'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Company'),
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
    else:
        cert = None

    return pankkiyhteys.key.Key(private_key, cert)


def sign_cert(key, *,
              not_valid_before=datetime.utcnow(),
              duration=timedelta(days=1)):
    """
    Helper function to create self signed certificate

    Returns:
        cryptography.x509.Certificate:
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'FI'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Company'),
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
