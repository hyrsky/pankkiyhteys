import unittest
import unittest.mock as mock
import random
import utils
from datetime import datetime

from lxml import etree
from lxml.builder import ElementMaker

import pankkiyhteys.banks as banks

class ServiceTestSuite(unittest.TestCase):
    def mock_client(self):
        class TestClient:
            username = '1234567890'
            country = 'FI'
            bank = random.choice(list(banks.Bank))
            environment = random.choice(list(banks.Environment))

        return TestClient()

    def test_signed_application_request(self):
        key = utils.create_test_key()

        E = ElementMaker(namespace="http://op.fi/mlp/xmldata/",
                         nsmap={None: "http://op.fi/mlp/xmldata/"})

        # Create application request (getCertificate with transfer key)
        request = E.CertApplicationRequest(
            E.CustomerId('1234567890'),
            E.Timestamp(datetime.utcnow().isoformat() + 'Z'),
            E.Environment(banks.Environment.TEST.name),
            E.SoftwareId('Unit test'),
            E.Service('MATU'),
        )

        # Validate ApplicationRequest schema
        with open('tests/xsd/CertApplicationRequest_200812.xsd') as xsd:
            schema = etree.XMLSchema(etree.parse(xsd))

        request = banks.ApplicationRequest(E, request)
        request.content(b'My test content')
        request.sign(key)

        root = etree.fromstring(request.to_string())

        schema.assertValid(root)

    def test_application_request(self):
        """
        Test ApplicationRequest against xsd schema
        """

        E = ElementMaker(namespace="http://op.fi/mlp/xmldata/",
                         nsmap={None: "http://op.fi/mlp/xmldata/"})

        # Create application request (getCertificate with transfer key)
        request = E.CertApplicationRequest(
            E.CustomerId('1234567890'),
            E.Timestamp(datetime.utcnow().isoformat() + 'Z'),
            E.Environment(banks.Environment.TEST.name),
            E.SoftwareId('Unit test'),
            E.Service('MATU'),
            E.Content(),  # Content placeholder
            E.TransferKey('1234567890123452')
        )

        # Validate ApplicationRequest schema
        with open('tests/xsd/CertApplicationRequest_200812.xsd') as xsd:
            schema = etree.XMLSchema(etree.parse(xsd))

        request = banks.ApplicationRequest(E, request)
        request.content(b'My test content')
        xml = etree.fromstring(request.to_string())

        schema.assertValid(xml)

        # Create application request (getCertificate with transfer key and compression)
        request = E.CertApplicationRequest(
            E.CustomerId('1234567890'),
            E.Timestamp(datetime.utcnow().isoformat() + 'Z'),
            E.Environment(banks.Environment.TEST.name),
            E.SoftwareId('Unit test'),
            E.Compression('true'),
            E.Service('MATU'),
            E.Content(),  # Content placeholder
            E.TransferKey('1234567890123452')
        )

        # Compress content
        request = banks.ApplicationRequest(E, request)
        print(request.to_string())
        request.content(b'My test content')
        xml = etree.fromstring(request.to_string())
        print(request.to_string())

        schema.assertValid(xml)

    def test_factory(self):
        """
        Test WebService and CertService factories
        """

        invalid_client = self.mock_client()
        invalid_client.bank = 'invalid bank'

        with self.assertRaises(NotImplementedError):
            banks.WebService.factory(invalid_client, invalid_client)
        with self.assertRaises(NotImplementedError):
            banks.CertService.factory(invalid_client, invalid_client)

        client = self.mock_client()

        service = banks.CertService.factory(client, self.mock_client())
        assert isinstance(service, banks.CertService)

        service = banks.WebService.factory(client, self.mock_client())
        assert isinstance(service, banks.WebService)

class OsuuspankkiWebServiceTestSuite(unittest.TestCase):
    pass

class OsuuspankkiCertServiceTestSuite(unittest.TestCase):
    def test_service_certificate(self):
        """
        Test getServiceCertificates call
        """

        client = mock.Mock()
        client.username = '1234567890'
        client.key = mock.Mock()
        client.country = 'FI'
        client.bank = banks.Bank.Osuuspankki
        client.environment = banks.Environment.TEST

        response = mock.Mock()
        response.ResponseHeader.ResponseCode = '00'
        response.ResponseHeader.ResponseText = 'OK.'
        response.ResponseHeader.Timestamp = datetime.utcnow()
        response.ApplicationResponse = '<ApplicationResponse></ApplicationResponse>'

        wsdl_client = mock.Mock()
        wsdl_client.service.getServiceCertificates.return_value = response

        # Action
        service = banks.OPCertService(client, wsdl_client)
        service.verify = mock.Mock()
        service.service_certificates()

        # Validate ApplicationRequest schema
        with open('tests/xsd/CertApplicationRequest_200812.xsd') as xsd:
            xml = etree.parse(xsd)
            schema = etree.XMLSchema(xml)

        assert wsdl_client.service.getServiceCertificates.called

        args, kwargs = wsdl_client.service.getServiceCertificates.call_args
        schema.assertValid(etree.fromstring(args[1]))

    def test_certificate(self):
        """
        Test getCertificate call with self signed certificate
        """

        # Setup
        key = utils.create_test_key()

        client = mock.Mock()
        client.username = '1234567890'
        client.key = key
        client.country = 'FI'
        client.bank = banks.Bank.Osuuspankki
        client.environment = banks.Environment.TEST

        response = mock.Mock()
        response.ResponseHeader.ResponseCode = '00'
        response.ResponseHeader.ResponseText = 'OK.'
        response.ResponseHeader.Timestamp = datetime.utcnow()
        response.ApplicationResponse = '<ApplicationResponse></ApplicationResponse>'

        wsdl_client = mock.Mock()
        wsdl_client.service.getCertificate.return_value = response

        # Action
        with mock.patch('pankkiyhteys.key.Key') as KeyMock:
            KeyMock.generate.return_value._private_key = mock.sentinel.private_key
            KeyMock.generate.return_value.generate_csr.return_value = b'my-test-value'
            KeyMock.return_value = mock.sentinel.new_key

            service = banks.OPCertService(client, wsdl_client)
            service.verify = mock.Mock()
            rv = service.certify()

            KeyMock.generate.assert_called_once()  # New key was generated
            KeyMock.assert_called_once_with(mock.sentinel.private_key, None)
            assert rv.data == mock.sentinel.new_key  # New key was returned
            assert client.key == mock.sentinel.new_key  # Client uses new key

        # Validate ApplicationRequest schema
        with open('tests/xsd/CertApplicationRequest_200812.xsd') as xsd:
            xml = etree.parse(xsd)
            schema = etree.XMLSchema(xml)

        assert wsdl_client.service.getCertificate.called  # Request to server called

        args, kwargs = wsdl_client.service.getCertificate.call_args
        schema.assertValid(etree.fromstring(args[1]))

    @mock.patch('pankkiyhteys.key.Key')
    def test_transfer_key(self, KeyMock):
        """
        Test getCertificate call with transfer key
        """

        # Setup
        key = mock.Mock()
        key.valid.return_value = False  # Mocked key has no certificate
        key.generate_csr.return_value = b'my-certificate'
        key._private_key = mock.sentinel.private_key

        client = mock.Mock()
        client.username = '1234567890'
        client.key = key
        client.bank = banks.Bank.Osuuspankki
        client.environment = banks.Environment.TEST

        response = mock.Mock()
        response.ResponseHeader.ResponseCode = '00'
        response.ResponseHeader.ResponseText = 'OK.'
        response.ResponseHeader.Timestamp = datetime.utcnow()
        response.ApplicationResponse = '<ApplicationResponse></ApplicationResponse>'

        wsdl_client = mock.Mock()
        wsdl_client.service.getCertificate.return_value = response

        # Action
        service = banks.OPCertService(client, wsdl_client)
        service.verify = mock.Mock()
        rv = service.certify(transfer_key='1234567890123452')

        # Existing key has no certificate so new key was not created
        KeyMock.return_value.generate.assert_not_called()
        assert rv.data == KeyMock.return_value
        args, kwargs = KeyMock.call_args
        assert args[0] == mock.sentinel.private_key

        # Validate ApplicationRequest schema
        with open('tests/xsd/CertApplicationRequest_200812.xsd') as xsd:
            schema = etree.XMLSchema(etree.parse(xsd))

            assert not key.sign.called  # Using transfer key
            assert wsdl_client.service.getCertificate.called  # Request to server called

            args, kwargs = wsdl_client.service.getCertificate.call_args
            xml = etree.fromstring(args[1])
            schema.assertValid(xml)
