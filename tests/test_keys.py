import unittest

from datetime import timedelta
from lxml import etree
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, serialization

import pankkiyhteys
import xmlsec
import io

from .utils import (
    create_test_key, generate_rsa_key, create_unsigned_application_request,
    assert_valid_schema, sign_cert)

SOAP_XML = """<soapenv:Envelope xmlns:tns="http://tests.python-zeep.org/"
        xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
    <soapenv:Header></soapenv:Header>
    <soapenv:Body>
        <tns:Function>
            <tns:Argument>OK</tns:Argument>
        </tns:Function>
    </soapenv:Body>
</soapenv:Envelope>"""


class TestXMLSigning(unittest.TestCase):
    def test_sign(self):
        """XML signed with sign() should successfully verify with xmlsec"""

        envelope = etree.fromstring(
            SOAP_XML, parser=etree.XMLParser(remove_blank_text=True))

        key = create_test_key()

        pankkiyhteys.key.sign(envelope, key)

        # print(etree.tostring(envelope, pretty_print=True).decode())

        signature_node = xmlsec.tree.find_node(
            envelope, xmlsec.constants.NodeSignature)

        # Verify - throws an error on failure
        ctx = xmlsec.SignatureContext()
        ctx.key = key.sign_key
        ctx.verify(signature_node)

    def test_verify(self):
        """XML signed with sign() should successfully verify with verify()"""

        envelope = etree.fromstring(
            SOAP_XML, parser=etree.XMLParser(remove_blank_text=True))

        key = create_test_key()

        pankkiyhteys.key.sign(envelope, key)

        # Verify - throws an error on failure
        pankkiyhteys.key.verify(envelope, key.certificate())


class CertificateHandlerTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    """TODO"""


class KeyTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load private with a password
        cls.key = create_test_key()
        cls.key_no_cert = create_test_key(create_cert=False)
        cls.password = b'mypassword'
        cls.protected_private_key = generate_rsa_key().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                cls.password))

    def test_invalid_keys(self):
        """Test loading invalid keys"""
        # Try invalid key type
        with self.assertRaises(ValueError):
            private_key = asymmetric.dsa.generate_private_key(
                key_size=1024,
                backend=default_backend())
            pankkiyhteys.key.Key(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

        # Try invalid key size
        with self.assertRaises(ValueError):
            private_key = generate_rsa_key(1024)
            pankkiyhteys.key.Key(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

        # Generate new key
        key = pankkiyhteys.key.Key.generate()
        private_key = key.private_key()
        assert isinstance(key, pankkiyhteys.key.Key)

    def test_passwords(self):
        """Test loading private key that has a password"""
        key = pankkiyhteys.key.Key(
            self.protected_private_key, password=self.password)
        assert isinstance(key, pankkiyhteys.key.Key)

    def test_export_key_with_password(self):
        """Test exporting private with password and then loading it again"""
        key = pankkiyhteys.key.Key(
            self.protected_private_key, password=self.password)
        protected_private_key = key.private_key(self.password)
        key = pankkiyhteys.key.Key(
            protected_private_key, password=self.password)
        assert isinstance(key, pankkiyhteys.key.Key)

    def test_wrong_password(self):
        """Test loading private key with incorrect password"""
        with self.assertRaises(ValueError):
            pankkiyhteys.key.Key(
                self.protected_private_key,
                password=b'notmypassword')

    def test_load_key_from_file(self):
        key = io.BytesIO()
        key.write(self.key.private_key())
        key.seek(0)

        cert = io.BytesIO()
        cert.write(self.key.certificate())
        cert.seek(0)

        key = pankkiyhteys.key.Key(key, cert)
        assert isinstance(key, pankkiyhteys.key.Key)

    def test_signature_schema(self):
        """Test xml signature schema"""

        root = create_unsigned_application_request()

        self.key.sign(root)

        # Validate signed document passess ApplicationRequest schema
        signature_node = xmlsec.tree.find_node(
            root, xmlsec.constants.NodeSignature)

        assert_valid_schema('xmldsig-core-schema.xsd', signature_node)

        # Verify signature
        ctx = xmlsec.SignatureContext()
        ctx.key = self.key.sign_key
        ctx.verify(signature_node)

    def test_key_without_certificate(self):
        # Try to export certificate
        with self.assertRaises(AttributeError):
            self.key_no_cert.certificate()

        # Try to check valid duration
        with self.assertRaises(AttributeError):
            self.key_no_cert.valid_duration

    def test_loading_certificate(self):
        # Try to load private key and self signed certificate
        cert = sign_cert(self.key_no_cert, duration=timedelta(days=1))
        key = pankkiyhteys.key.Key(self.key_no_cert.private_key(), cert)
        assert isinstance(key, pankkiyhteys.key.Key)
        assert timedelta(hours=23) < key.valid_duration <= timedelta(days=1)

    def test_exporting_certificate(self):
        # Export certificate and try to load it
        cert = self.key.certificate()
        key = pankkiyhteys.key.Key(self.key.private_key(), cert)
        assert isinstance(key, pankkiyhteys.key.Key)
