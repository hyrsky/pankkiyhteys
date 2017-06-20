from lxml import etree
from lxml.builder import ElementMaker

from enum import Enum, auto
from datetime import datetime

import logging
import base64
import gzip
import random
import abc

SOFTWARE_ID = 'pankkiyhteys v0.1'
"""
Client software identifier sent to bank on each request
"""

class Bank(Enum):
    Osuuspankki = auto()

class Environment(Enum):
    PRODUCTION = 0
    TEST = 1

class ApplicationRequest:
    def __init__(self, E, root):
        self.E = E
        self.root = root

        compress = self.root.find('Compression', namespaces=self.root.nsmap)

        # Should compress content
        self.compress = False if compress is None else compress.text.upper() == 'TRUE'

        # Set compression method to RFC1952
        if self.compress:
            method = self.root.find('CompressionMethod', namespaces=self.root.nsmap)
            if method is None:
                compress.addnext(E.CompressionMethod('RFC1952'))
            else:
                method.text = 'RFC1952'

    def content(self, value):
        """Set content"""

        # Compress data
        if self.compress:
            value = gzip.compress(value)

        # Encode data
        value = base64.b64encode(value).decode()

        # Save data
        content = self.root.find('Content', namespaces=self.root.nsmap)
        if content is None:
            self.root.append(self.E.Content(value))
        else:
            content.text = value

    def append(self, *args, **kwargs):
        self.root.append(*args, **kwargs)

    def sign(self, key):
        """Add xml signature to this request"""
        self.root = key.sign(self.root)

    def to_string(self, pretty_print=False):
        return etree.tostring(
            self.root,
            xml_declaration=True,
            encoding='UTF-8',
            pretty_print=pretty_print
        )

class WebService(metaclass=abc.ABCMeta):
    def __init__(self, client, service):
        self.client = client
        self.service = service
        self.logger = logging.getLogger(__name__)

    @classmethod
    def factory(cls, client, service):
        for subcls in cls.__subclasses__():
            if subcls.bank == client.bank:
                return subcls(client, service)
        raise NotImplementedError(str(client.bank) + ' not implemented')

    @abc.abstractmethod
    def file_list(self, *, status='NEW', start_date=None, end_date=None):
        """
        Get list of files

        Args:
            status (NEW|DLD): Filter new or downloaded files
            start_date (Datetime): Filter by time
            end_date (Datetime): Filter by time
        """

    @abc.abstractmethod
    def get_file(self, key):
        pass

    @abc.abstractmethod
    def upload_file(self, key):
        pass

class CertService(metaclass=abc.ABCMeta):
    def __init__(self, client, service):
        self.client = client
        self.service = service
        self.logger = logging.getLogger(__name__)

    @classmethod
    def factory(cls, client, service):
        for subcls in cls.__subclasses__():
            if subcls.bank == client.bank:
                return subcls(client, service)
        raise NotImplementedError(str(client.bank) + ' not implemented')

    @abc.abstractmethod
    def certify(self, *, transfer_key=None):
        """
        Request signed certificate from bank key service

        Args:
            transfer_key (str): 16 digit one-time key required to prove identity when
                requesting the first certificate. User must register with the bank to
                get this key. Transfer key must be used if no valid certificate is
                available, othervise the existing certificate can used to to prove
                identity.

        Raises:
            Exception: Unable to load key
            Exception: Communication error

        Returns:
            pankkiyhteys.key.Key: Certified key object. Make sure to
                save the certificate afterwards
        """

class OPService:
    """
    Osuuspankki service base class
    """

    @property
    def request_id(self):
        """
        Request id generator. Yield strings with format
        YYYYMMDDXXXXX where x is number between [00001-99999]
        """
        def generator():
            today = value = 0
            while True:
                if today != datetime.utcnow().date():
                    value = random.randint(0, 99999)
                    today = datetime.utcnow().date()
                value = (value + 1) % 100000
                yield today.strftime('%Y%m%d{}').format(value)

        if not hasattr(self, '_request_id'):
            self._request_id = generator()

        return self._request_id

    def sign(self, request, *, transfer_key=None):
        """
        Attach signature to request data. If key has no valid certificate
        transfer key can be attached instead, but it should only be used to
        request a first certificate.

        It goes without saying that after this call ApplicationRequest should
        not be modified.

        Args:
            request (ApplicationRequest): Request data
            transfer_key (string, optional): One-time key

        Raises:
            AttributeError: If there is no valid certificate or the
                transfer key is invalid.

        """
        def luhn(n):
            """Luhn mod 10 checksum by Hans Peter Luhn (1896-1964)"""
            sum = 0
            while n:
                r, n = n % 100, n // 100
                z, r = r % 10, r // 10 * 2
                sum += r // 10 + r % 10 + z
            return 0 == sum % 10

        # Sign certificate request with existing key
        if self.client.key.valid():
            request.sign(self.client.key)

        # Use one-time transfer key
        elif transfer_key is not None:
            # Validate transfer key with luhn algorithm
            if not luhn(int(transfer_key)):
                raise AttributeError('Invalid transfer key')

            # Append TransferKey element to xml
            request.append(request.E.TransferKey(transfer_key))

        else:
            raise AttributeError('Key has no certificate')


class OPWebService(WebService, OPService):
    bank = Bank.Osuuspankki

    def file_list(self, *, status='NEW', start_date=None, end_date=None):
        pass

    def get_file(self, key):
        pass

    def upload_file(self, key):
        pass

class OPCertService(CertService, OPService):
    bank = Bank.Osuuspankki

    class CertApplicationRequest(ApplicationRequest):
        E = ElementMaker(namespace="http://op.fi/mlp/xmldata/",
                         nsmap={None: "http://op.fi/mlp/xmldata/"})

        def __init__(self, root):
            super().__init__(OPCertService.CertApplicationRequest.E, root)

        @classmethod
        def get_certificate(cls, client):
            request = cls.E.CertApplicationRequest(
                cls.E.CustomerId(client.username),
                cls.E.Timestamp(datetime.utcnow().isoformat() + 'Z'),
                cls.E.Environment(client.environment.name),
                cls.E.SoftwareId(SOFTWARE_ID),
                cls.E.Service('MATU'),
            )

            return cls(request)

        @classmethod
        def get_service_certificates(cls, client):
            request = cls.E.CertApplicationRequest(
                cls.E.CustomerId(client.username),
                cls.E.Timestamp(datetime.utcnow().isoformat() + 'Z'),
                cls.E.Environment(client.environment.name),
                cls.E.SoftwareId(SOFTWARE_ID),
                cls.E.Service('MATU'),
            )

            return cls(request)

    def _request_header(self):
        return self.service.get_type('ns0:CertificateRequestHeader')(
            SenderId=self.client.username,
            RequestId=next(self.request_id),
            Timestamp=datetime.utcnow()
        )

    def get_certificates(self):
        request = (OPCertService.CertApplicationRequest
                                .get_service_certificates(self.client))

        # Make request
        response = self.service.service.getServiceCertificates(
            self._request_header(), request.to_string()  # zeep will b64encode string
        )

        # Handle response
        return response

    def certify(self, *, transfer_key=None):
        csr = self.client.key.generate_csr(self.client)

        # Generate new certificate signing request
        request = OPCertService.CertApplicationRequest.get_certificate(self.client)
        request.content(csr)

        # Sign or attach transfer key
        self.sign(request, transfer_key=transfer_key)

        # Make request
        response = self.service.service.getCertificate(
            self._request_header(), request.to_string()  # zeep will b64encode string
        )

        # Handle response
        return response
