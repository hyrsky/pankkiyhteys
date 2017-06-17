"""
Examples:
    Create client

        client = Client('1234567890', Banks.Osuuspankki)
        client.cert_service.certify()

Todo:
    * How to load key+cert and pass them around in the library
"""
import zeep

import collections

from pankkiyhteys.banks import Bank, Environment, CertService, WebService

class Client(object):
    Services = collections.namedtuple('Services', ['web_service', 'cert_service'])
    wsdl = {
        Bank.Osuuspankki: (
            # Production environment:
            Services('https://wsk.op.fi/wsdl/MaksuliikeWS.xml',
                     'https://wsk.op.fi/wsdl/MaksuliikeCertService.xml'),
            # Testing environment:
            Services('https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeWS.xml',
                     'https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeCertService.xml')
        )
    }

    def __init__(self, username, bank, *, environment=Environment.PRODUCTION):
        """
        Construct pankkiyhteys object.

        Args:
            username (string): 10 digit username
            bank (pankkiyhteys.Bank): Which bank to connect to from a list of
                supported banks
            environment (pankkiyhteys.Environment): Use production or testing
                environment. To use testing enviroment one might have to make
                separate contract with the bank and use different keys than in
                production
        """

        self.bank = bank
        self.username = username
        self.environment = environment

        # lazy load clients later
        self.clients = self.__class__.Services(None, None)

    country = 'FI'

    def _create_client(self, service):
        return zeep.Client(
            getattr(self.__class__.wsdl[self.bank][self.environment.value], service),
            transport=zeep.transports.Transport(
                cache=zeep.cache.InMemoryCache()
            )
        )

    @property
    def web_service(self):
        """Lazy load web service client"""
        if self.clients.web_service is None:
            self.clients.web_service = self._create_client('web_service')

        return WebService.factory(self.clients.web_service, self)

    @property
    def cert_service(self):
        """Lazy load cert service client"""
        if self.clients.cert_client is None:
            self.clients.cert_service = self._create_client('cert_service')

        return CertService.factory(self.clients.cert_service, self)
