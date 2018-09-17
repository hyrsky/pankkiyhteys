from enum import Enum

from lxml import etree
from lxml.etree import QName

import pytz
from datetime import datetime
from dateutil import parser

SOAP_ENV = 'http://schemas.xmlsoap.org/soap/envelope/'
XLINK = 'http://www.w3.org/1999/xlink'
XSI = 'https://www.w3.org/2001/XMLSchema-instance'
EB = 'http://www.oasisopen.org/committees/ebxml-msg/schema/msg-header-2_0.xsd'
FINVOICE = 'http://www.finanssiala.fi/finvoice/dokumentit/Finvoice.xsd'


class Command(Enum):
    ADD = 'ADD'
    CHANGE = 'CHANGE'
    DELETE = 'DELETE'


class ReceiverNotice:

    def __init__(self, identifier, command, timestamp, einvoice_address,
                 intermediator, name, address, postal_code, city,
                 country=None, proposed_due_date=None):
        self.identifier = identifier
        self.command = command
        self.timestamp = timestamp
        self.einvoice_address = einvoice_address
        self.intermediator = intermediator
        self.name = name
        self.address = address
        self.postal_code = postal_code
        self.city = city
        self.country = country
        self.proposed_due_date = proposed_due_date

    @classmethod
    def parse(cls, document):
        """Parse FinvoiceReceiverInfo XML document"""

        root = etree.fromstring(document)

        try:
            command = cls.Command[root.findtext('MessageDetails/MessageActionCode')]
        except KeyError as err:
            raise NotImplementedError('Command {} not implemented'.format(err))

        timestamp = parser.parse(root.findtext('ReceiverInfoTimeStamp'))

        name = root.findtext('BuyerPartyDetails/BuyerOrganisationName').title()
        postal_address = root.find('BuyerPartyDetails/BuyerPostalAddressDetails')

        if postal_address is not None:
            address = postal_address.findtext('BuyerStreetName', default='').title()
            city = postal_address.findtext('BuyerTownName', default='').title()
            postal_code = postal_address.findtext('BuyerPostCodeIdentifier', default='')
            country = postal_address.findtext('CountryName', default='').title()

        else:
            address = None
            city = None
            postal_code = None
            country = None

        recipient = root.find('InvoiceRecipientDetails')

        if recipient is not None:
            identifier = recipient.findtext('SellerInvoiceIdentifier')
            einvoice_address = recipient.findtext('InvoiceRecipientAddress')
            intermediator = recipient.findtext('InvoiceRecipientIntermediatorAddress')
            proposed_due_date = recipient.findtext('ProposedDueDate')

        return cls(identifier, command, timestamp, einvoice_address,
                   intermediator, name, address, postal_code, city, country,
                   proposed_due_date)

def _create_eb_header(document_id, sender, receiver):
    def create_eb_entity(destination, party_id, role):
        elm = etree.Element(QName(EB, destination))
        etree.SubElement(elm, QName(EB, 'PartyId')).text = party_id
        etree.SubElement(elm, QName(EB, 'Role')).text = role
        return elm

    msg_header = etree.Element(QName(EB, 'MessageHeader'))
    msg_header.set(QName(SOAP_ENV, 'mustUnderstand'), '1')
    msg_header.set(QName(EB, 'version'), '2.0')

    # Create eb:From and eb:To elements
    msg_header.append(create_eb_entity('From', sender.id, 'Sender'))
    msg_header.append(create_eb_entity('From', sender.intermediator, 'Intermediator'))
    msg_header.append(create_eb_entity('To', receiver.id, 'Receiver'))
    msg_header.append(create_eb_entity('To', receiver.intermediator, 'Intermediator'))

    etree.SubElement(msg_header, QName(EB, 'CPAId')).text = 'yoursandmycpa'
    etree.SubElement(msg_header, QName(EB, 'ConversationId'))
    etree.SubElement(msg_header, QName(EB, 'Service')).text = 'Routing'
    etree.SubElement(msg_header, QName(EB, 'Action')).text = 'ProcessInvoice'

    msg_data = etree.SubElement(msg_header, QName(EB, 'MessageData'))
    etree.SubElement(msg_data, QName(EB, 'MessageId')).text = document_id
    etree.SubElement(msg_data, QName(EB, 'Timestamp')).text = (
        datetime.now(pytz.utc).replace(microsecond=0).isoformat())

    return msg_header

def _create_eb_body(document_id):
    manifest = etree.Element(QName(EB, 'Manifest'))
    manifest.set(QName(EB, 'id'), 'Manifest')
    manifest.set(QName(EB, 'version'), '2.0')
    reference = etree.SubElement(manifest, QName(EB, 'Reference'))
    reference.set(QName(EB, 'id'), 'Finvoice')
    reference.set(QName(XLINK, 'href'), document_id)
    schema = etree.SubElement(reference, QName(EB, 'schema'))
    schema.set(QName(EB, 'location'), FINVOICE)
    schema.set(QName(EB, 'version'), '2.0')

def _create_finvoice_transmission_details(invoice_id, sender, receiver):
    def create_party_details(role, destination, entity):
        t = etree.Element('Message{}Details'.format(role))
        etree.SubElement(t, '{}Identifier'.format(destination), entity.id)
        etree.SubElement(t, '{}Intermediator'.format(destination), entity.intermediator)
        return t

    tx_details = etree.Element('MessageTransmissionDetails')
    tx_details.append(create_party_details('Sender', 'To', sender))
    tx_details.append(create_party_details('Receiver', 'From', receiver))

    msg_details = etree.SubElement(tx_details, 'MessageDetails')
    etree.SubElement(msg_details, 'MessageIdentifier').text = invoice_id
    etree.SubElement(msg_details, 'MessageTimeStamp').text = (
        datetime.now(pytz.utc).replace(microsecond=0).isoformat())

    return tx_details

def _create_finvoice_party_details(party, entity):
    details = etree.Element('{}PartyDetails'.format(party))

    etree.SubElement('{}PartyIdentifier'.format(party)).text = entity.name
    etree.SubElement('{}OrganisationName'.format(party)).text = entity.name

    address = etree.SubElement(details, '{}PostalAddressDetails'.format(party))
    etree.SubElement(address, '{}StreetName'.format(party)).text = entity.address
    etree.SubElement(address, '{}TownName'.format(party)).text = entity.city
    etree.SubElement(address, '{}PostCodeIdentifier'.format(party)).text = (
        entity.postal_code)
    etree.SubElement(address, '{}CountryCode'.format(party)).text = entity.country

class Finvoice:
    def __init__(self, id, receiver, sender, amount):
        """
        Args:
            id (int): Invoice id
            receiver (pankkiyhteys.Entity): Receiver details
            sender (pankkiyhteys.Entity): Sender details
            amount (double): Invoice amount
        """

        self.envelope = etree.Element(QName(SOAP_ENV, 'Envelope'),
                                      nsmap={None: SOAP_ENV, 'xlink': XLINK, 'eb': EB})

        header = etree.SubElement(self.envelope, QName(SOAP_ENV, 'Header'))
        header.append(_create_eb_header(id, receiver, sender))

        body = etree.SubElement(self.envelope, QName(SOAP_ENV, 'Body'))
        body.append(_create_eb_body())

        self.finvoice = etree.Element('Finvoice', nsmap={'xsi': XSI})
        self.finvoice.set(QName(XSI, 'noNamespaceSchemaLocation'), "Finvoice2.01.xsd")

        self.finvoice.append(_create_finvoice_transmission_details(id, receiver, sender))
        self.finvoice.append(_create_finvoice_party_details('Seller', sender))

        information = etree.SubElement(self.finvoice, 'SellerInformationDetails')
        etree.SubElement(information, 'SellerPhoneNumber').text = sender.phone
        etree.SubElement(information, 'SellerCommonEmailaddressIdentifier').text = (
            sender.email
        )
        etree.SubElement(information, 'SellerWebAddressIdentifier').text = sender.website
        accounts = etree.SubElement(information, 'SellerAccountDetails')
        for account in sender.accounts:
            etree.SubElement(accounts, 'SellerAccountID').text = account.number
            etree.SubElement(accounts, 'SellerBic').text = account.bank

        self.finvoice.append(_create_finvoice_party_details('Buyer', receiver))


def _list_receiver_notices(client, start_date, end_date):
    pass

def _download_receiver_notice(client, file):
    pass

def receiver_notices(client, *, status='NEW', start_date=None, end_date=None):
    """
    Get list of receiver notices

    Returns:
        iter: iteratable receiver notices
    """
    pass

def send_invoices(client, invoices):
    """
    Send invoices
    """
    pass
