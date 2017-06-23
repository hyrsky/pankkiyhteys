import unittest
import unittest.mock as mock

from pankkiyhteys import Client, Bank
from pankkiyhteys.banks import WebService, CertService, Environment

class ClientTestSuite(unittest.TestCase):
    @mock.patch.object(WebService, 'factory')
    @mock.patch.object(CertService, 'factory')
    def test_get_services(self, cert_factory_mock, web_factory_mock):
        web_factory_mock.return_value = mock.sentinel.web_service
        cert_factory_mock.return_value = mock.sentinel.cert_service

        bank = Bank.Osuuspankki
        environment = Environment.TEST

        key = mock.Mock()

        client = Client('1234567890', key, bank=bank, environment=environment)

        with mock.patch('zeep.Client'):
            assert client.web_service == mock.sentinel.web_service
            assert client.cert_service == mock.sentinel.cert_service

            # Run second time -> should not create new instance
            assert client.web_service == mock.sentinel.web_service
            assert client.cert_service == mock.sentinel.cert_service

        # Created only one instance
        web_factory_mock.assert_called_once()
        cert_factory_mock.assert_called_once()
