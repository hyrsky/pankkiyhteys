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
from zeep.utils import detect_soap_env
import zeep.wsse

import base64
import signxml
from uuid import uuid4
from lxml import etree
from lxml.builder import ElementMaker

from datetime import datetime, timedelta

import collections

from pankkiyhteys.banks import Bank, Environment, CertService, WebService

class WSSEPlugin(zeep.wsse.signature.MemorySignature):
    WSU = ElementMaker(namespace=zeep.ns.WSU, nsmap={'wsu': zeep.ns.WSU})
    WSSE = ElementMaker(namespace=zeep.ns.WSSE, nsmap={'wsse': zeep.ns.WSSE})
    DS = ElementMaker(namespace='http://www.w3.org/2000/09/xmldsig#',
                      nsmap={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
    VALUE_TYPE = ('http://docs.oasis-open.org/wss/2004/01/' +
                  'oasis-200401-wss-x509-token-profile-1.0#X509v3')
    ENCODING_TYPE = ('http://docs.oasis-open.org/wss/2004/01/' +
                     'oasis-200401-wss-soap-message-security-1.0#Base64Binary')

    """
    Zeep already has a nice wsse built-in, but it uses xmlsec,
    which relies relies heavily on compiled libraries that are
    hard to use with AWS lambda
    """

    def __init__(self, client):
        self.client = client

    def _ensure_id(self, node):
        id_val = node.get(zeep.wsse.utils.ID_ATTR)
        if not id_val:
            id_val = str(uuid4())
            node.set(zeep.wsse.utils.ID_ATTR, id_val)
        return id_val

    def apply(self, envelope, headers):
        WSSE = WSSEPlugin.WSSE
        WSU = WSSEPlugin.WSU
        DS = WSSEPlugin.DS

        soap_env = detect_soap_env(envelope)

        # Create wsse:Security header
        security = zeep.wsse.utils.get_security_header(envelope)
        security.set(etree.QName(soap_env, 'mustUnderstand'), '1')

        # Create wsu:Timestamp
        timestamp = WSU.Timestamp(
            WSU.Created(datetime.utcnow().isoformat() + 'Z'),
            WSU.Expires((datetime.utcnow() + timedelta(hours=12)).isoformat() + 'Z'))

        security.append(timestamp)

        # Add X509 certificate
        binary_token = etree.Element(etree.QName(zeep.ns.WSSE, 'BinarySecurityToken'),
                                     ValueType=WSSEPlugin.VALUE_TYPE,
                                     EncodingType=WSSEPlugin.ENCODING_TYPE,
                                     nsmap={'wsu': zeep.ns.WSU})
        binary_token.text = base64.b64encode(self.client.key.certificate())

        # Add wsu:Id attributes to body and timestamp, these will be signed
        body_id = self._ensure_id(envelope.find(etree.QName(soap_env, 'Body')))
        timestamp_id = self._ensure_id(timestamp)
        binary_token_id = self._ensure_id(binary_token)

        # Sign body and timestamp
        signature = self.client.key.sign(
            envelope,
            method=signxml.methods.detached,
            reference_uri=[timestamp_id, body_id],
            key_info=DS.KeyInfo(WSSE.SecurityTokenReference(WSSE.Reference(
                URI=binary_token_id, ValueType=WSSEPlugin.VALUE_TYPE
            )))
        )

        # Insert the Signature node in the wsse:Security header.
        security.insert(0, signature)
        security.insert(0, binary_token)

        return envelope, headers

    def verify(self, envelope):
        return envelope

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

    def _create_client(self, wsdl, wsse=None):
        return zeep.Client(
            wsdl, transport=zeep.transports.Transport(cache=InMemoryCache()),
            wsse=wsse
        )

    @property
    def web_service(self):
        """Get web service client"""
        if self._web_service is None:
            self._web_service = WebService.factory(
                self, self._create_client(self._wsdl.web_service), WSSEPlugin(self)
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
