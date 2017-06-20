"""
Examples:
    Create client

        client = Client('1234567890', Key(private, cert), bank=Bank.Osuuspankki)
        client.cert_service.certify()

Todo:
    * How to load key+cert and pass them around in the library
"""

import zeep
from zeep.cache import InMemoryCache
import collections

from pankkiyhteys.banks import Bank, Environment, CertService, WebService

class Client(object):
    Services = collections.namedtuple('Services', ['web_service', 'cert_service'])
    wsdl = {
        Bank.Osuuspankki: [
            # Production environment:
            Services('https://wsk.op.fi/wsdl/MaksuliikeWS.xml',
                     'https://wsk.op.fi/wsdl/MaksuliikeCertService.xml'),
            # Testing environment:
            Services('https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeWS.xml',
                     'https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeCertService.xml')
        ]
    }

    country = 'FI'

    def __init__(self, username, key, *, bank, environment=Environment.PRODUCTION):
        """
        Construct pankkiyhteys object.

        Args:
            username (string): 10 digit username
            bank (pankkiyhteys.Bank): Which bank to connect to from a list of
                supported banks
            environment (pankkiyhteys.Environment): Production or testing
                environment. Testing enviroment might need separate contract
                with the bank and keys.
            key (pankkiyhteys.Key): Key object containing credentials
        """

        self.username = username
        self.key = key
        self.bank = bank
        self.environment = environment

        # Not all users need both services -> lazy load later
        self._web_service = None
        self._cert_service = None

    @property
    def _wsdl(self):
        return Client.wsdl[self.bank][self.environment.value]

    def _create_client(self, wsdl):
        return zeep.Client(
            wsdl, transport=zeep.transports.Transport(cache=InMemoryCache())
        )

    @property
    def web_service(self):
        """Get web service client"""
        if self._web_service is None:
            self._web_service = WebService.factory(
                self, self._create_client(self._wsdl.web_service)
            )
        return self._web_service

    @property
    def cert_service(self):
        """Get cert service client"""
        if self._cert_service is None:
            self._cert_service = CertService.factory(
                self, self._create_client(self._wsdl.cert_service)
            )
        return self._cert_service
