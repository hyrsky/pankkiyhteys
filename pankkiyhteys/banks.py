from lxml import etree
from lxml.builder import E

from enum import Enum, auto
from datetime import datetime
import base64
import abc

SOFTWARE_ID = 'pankkiyhteys v0.1'
"""
Client software identifier sent to bank on each request
"""

class Bank(Enum):
    Osuuspankki = auto()

class Environment(Enum):
    PRODUCTION = 0
    TEST = 1,

class ApplicationRequest:
    def __init__(self, tree):
        self.tree = tree

    def to_string(self, pretty_print=False):
        return etree.tostring(
            self.tree,
            xml_declaration=True,
            encoding='UTF-8',
            pretty_print=pretty_print
        )

    def to_base64(self):
        return base64.b64encode(self.to_string())

    def __str__(self):
        return self.to_string(pretty_print=True).decode()

class WebService(metaclass=abc.ABCMeta):
    def __init__(self, service, client):
        self.service = service
        self.client = client

    @classmethod
    def factory(cls, service, client):
        for subcls in cls.__subclasses__():
            if subcls.bank == client.bank:
                return subcls(service, client)
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
        pass

    @abc.abstractmethod
    def get_file(self, key):
        pass

    @abc.abstractmethod
    def upload_file(self, key):
        pass

class CertService(metaclass=abc.ABCMeta):
    def __init__(self, service, client):
        self.service = service
        self.client = client

    @classmethod
    def factory(cls, service, client):
        for subcls in cls.__subclasses__():
            if subcls.bank == client.bank:
                return subcls(service, client)
        raise NotImplementedError(str(client.bank) + ' not implemented')

    @abc.abstractmethod
    def certify(self, key, *, transfer_key=None):
        """
        Get new certificate
        """
        pass

class OPCertService(CertService):
    bank = Bank.Osuuspankki

    def certify(self, key):
        tree = E.CertApplicationRequest(
            E.CustomerId(self.client.username),
            E.Timestamp(datetime.utcnow() + 'Z'),
            E.Environment(self.client.environment.value),
            E.SoftwareId(SOFTWARE_ID),
        )
        request = ApplicationRequest(tree)

        # self.service.

        print(str(request))
