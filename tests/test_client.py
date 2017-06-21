import unittest
import unittest.mock as mock

from lxml import etree

from pankkiyhteys import Client, Bank
from pankkiyhteys.banks import WebService, CertService, Environment
import pankkiyhteys

import utils

class ClientTestSuite(unittest.TestCase):
    def test_wsse(self):
        parser = etree.XMLParser(remove_blank_text=True)
        envelope = etree.fromstring("""
            <soapenv:Envelope
                xmlns:tns="http://tests.python-zeep.org/"
                xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
              <soapenv:Header></soapenv:Header>
              <soapenv:Body>
                <tns:Function>
                  <tns:Argument>OK</tns:Argument>
                </tns:Function>
              </soapenv:Body>
            </soapenv:Envelope>
        """, parser=parser)

        client = mock.Mock()
        client.key = utils.create_test_key()

        wsse = pankkiyhteys.client.WSSEPlugin(client)
        envelope, headers = wsse.apply(envelope, None)

        print(etree.tostring(envelope, pretty_print=True).decode())

        # assert False

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
