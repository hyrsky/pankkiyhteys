"""
Examples:
    Create client

        client = Osuuspankki('1234567890', Key(private, cert))
        client.cert_service.certify()

Todo:
    * How to load key+cert and pass them around in the library
"""

from enum import Enum

from .key import Key, CertificateHandler
from .services import Services, WebServiceMixin, CertServiceMixin
from .messages import Response

import os
import base64
import zeep
import zeep.wsse
import zeep.cache
import logging


class Environment(Enum):
    PRODUCTION = 0
    TEST = 1


class LazyServiceClient:
    """
    Lazy load WSDL client.

    Loading and parsing WSDL document takes time. This utility defers that
    until the client is actually used.

    This is more efficient because not all applications require all services.
    """

    def __init__(self, name, endpoint, *,
                 sign_requests=True,
                 cert_handler=None):
        self.name = name
        self.endpoint = endpoint

        self._client = None
        self._cert_handler = cert_handler if sign_requests else None

    @property
    def client(self):
        if self._client is None:
            self.init()

        return self._client

    def init(self):
        """Fetch web service description and initialize client"""
        logger = logging.getLogger(__name__)
        logger.debug('Reading WSDL file at %s', self.endpoint)

        cache = zeep.cache.InMemoryCache()
        transport = zeep.transports.Transport(cache=cache)
        self._client = zeep.Client(
            self.endpoint,
            transport=transport,
            wsse=self._cert_handler)


class Pankkiyhteys:
    """
    Pankkiyhteys client base class
    """

    country = 'FI'
    language = 'FI'

    def __init__(self, username, key, cert, *,
                 bic, bank, cert_handler,
                 password=None,
                 environment=Environment.PRODUCTION):
        """
        Construct pankkiyhteys client.

        Args:
            username (string): 10 digit username
            key (pankkiyhteys.Key): Key object containing credentials
            bank (dict): Bank service description
            environment (pankkiyhteys.Environment): Production or testing
                environment. Testing enviroment might need separate contract
                with the bank.
        """

        self.logger = logging.getLogger(__name__)
        self.services = {}
        self.username = username
        self.key = Key(key, cert=cert, password=password)
        self.bank = bank
        self.bic = bic
        self.environment = environment

        # Initialize signature handler
        ca = bank['ca'][environment.name.lower()]
        self.cert_handler = cert_handler
        self.cert_handler.init(self.key, ca, bank['crl'], self.logger)

        for service in bank['services']:
            name = service['name']
            endpoint = service[environment.name.lower()]
            service = LazyServiceClient(
                name, endpoint,
                sign_requests=service.get('sign_requests', True),
                cert_handler=self.cert_handler)

            self.logger.info('Registering %s (%s) service <%s>',
                             name, environment.name, endpoint)

            self.services[name] = service

    def get_client(self, name):
        """Get client by service name

        Returns:
            zeep.Client: Service client
        """
        return self.services[name].client


class Osuuspankki(Pankkiyhteys, WebServiceMixin, CertServiceMixin):
    """
    Osuuspankki client
    """

    def __init__(self, username, key, cert, *,
                 password=None,
                 environment=Environment.PRODUCTION,
                 cert_handler=CertificateHandler()):

        def read_cert(filename):
            path = os.path.join(os.path.dirname(__file__), "cacerts", filename)
            with open(path, "rb") as f:
                return f.read()

        # Osuuspankki variables
        bank = {
            "crl": "http://wsk.op.fi/crl/ws/OP-Pohjola-ws.crl",
            "ca": {
                "production": read_cert("OP-Pohjola_Root_CA_for_WS.cer"),
                "test": read_cert("TESTOP-PohjolaRootCA.cer")
            },
            "services": [{
                "name": Services.WEB_SERVICE,
                "production": "https://wsk.op.fi/wsdl/MaksuliikeWS.xml",
                "test": "https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeWS.xml",
            }, {
                "name": Services.CERT_SERVICE,
                "production": "https://wsk.op.fi/wsdl/MaksuliikeCertService.xml",  # noqa
                "test": "https://wsk.asiakastesti.op.fi/wsdl/MaksuliikeCertService.xml",  # noqa
                "namespace": "http://op.fi/mlp/xmldata/",
                "sign_requests": False
            }]
        }

        super().__init__(username, key, cert,
                         bic="OKOYFIHH",
                         bank=bank,
                         environment=environment,
                         cert_handler=cert_handler)

        # Load intermediary certificates form OP cert service
        response = self.get_service_certificates()
        if response["ResponseCode"] == Response.SUCCESSS:
            for cert in response.get("Certificates", []):
                data = base64.b64decode(cert["Certificate"])
                self.cert_handler.add_intermediary(data)
