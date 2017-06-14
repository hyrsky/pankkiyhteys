import zeep

from enum import Enum, IntEnum, auto
import collections

class Bank(Enum):
    Osuuspankki = auto()

class Environment(IntEnum):
    PRODUCTION = 0
    TEST = 1,


Services = collections.namedtuple('Services', ['web_service', 'cert_service'])
wsdl = {
    Bank.Osuuspankki: (
        Services('https://wsk.op.fi/wsdl/MaksuliikeWS.xml',
                 'https://wsk.op.fi/wsdl/MaksuliikeCertService.xml'),
        Services('https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeWS.xml',
                 'https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeCertService.xml')
    )
}

class CertificateServiceClient(object):
    def __init__(self, client):
        self.client = client


class Client(object):

    def __init__(self, username, bank, environment=Environment.PRODUCTION):
        """
        Construct pankkiyhteys object.

        Args:
            username (string): 10 digit username
            bank (pankkiyhteys.Bank): Which bank to connect to from a list of
                supported banks
            environment (pankkiyhteys.Environment): Use production or testing
                environment. To use testing enviroment one might need to make
                separate contract with the bank and use different keys than in
                production
        """

        self.bank = bank
        self.username = username
        self.environment = environment

        # lazy load clients later
        self.clients = Services(None, None)

    country = 'FI'

    def _client_settings():
        return {
            'transport': zeep.transports.Transport(
                cache=zeep.cache.InMemoryCache()
            )
        }

    @property
    def web_service(self):
        """Lazy load web service client"""
        if self.clients.web_service is None:
            self.clients.web_service = zeep.Client(
                wsdl[self.bank][self.environment.value].web_service,
                **self._client_settings
            )
        return self.clients.web_service

    @property
    def cert_service(self):
        """Lazy load cert service client"""
        if self.wsdl.cert_client is None:
            self.clients.web_service = zeep.Client(
                wsdl[self.bank][self.environment.value].web_service,
                **self._client_settings
            )

        return self.clients.cert_service
