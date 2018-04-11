from lxml import etree
from datetime import datetime, date
from collections import OrderedDict

from .utils import luhn

import gzip
import base64
import xmlsec


def _populate_element(element, d):
    """Serialize dictionary to XML"""

    for key, value in d.items():
        child = etree.SubElement(element, key)
        if isinstance(value, dict):
            # Serialize the child dictionary
            _populate_element(child, value)
        elif isinstance(value, list):
            # Can only serialize lists with dictionaries
            # [{"Key": "Value 1"}, {"Key": "Value 2"}]
            for item in value:
                if not isinstance(item, dict):
                    raise TypeError('List can only contain dictionaries')

                _populate_element(child, item)
        elif isinstance(value, datetime):
            child.text = value.isoformat(timespec='seconds')
        elif isinstance(value, date):
            child.text = value.isoformat()
        elif type(value) is bool:
            child.text = str(value).lower()
        else:
            child.text = str(value)


def _unmarshall(res, element):
    def is_list(iterator):
        iterator = iter(iterator)
        try:
            first = next(iterator)
        except StopIteration:
            return True
        return all(first == rest for rest in iterator)

    tag = etree.QName(element)

    # Skip tags:
    if tag.localname in ('Compressed', 'CompressionMethod'):
        return

    # Skip signature
    if tag.namespace == xmlsec.constants.DSigNs:
        return

    # Element does not have children
    if not len(element):
        value = dict(element.attrib)
        if value and element.text:
            value['text'] = element.text
        else:
            value = element.text
        res[tag.localname] = value

    # All children are the same
    elif is_list(map(etree.QName, element)):
        values = []
        for child in element:
            values.append(_unmarshall({}, child))

        res[tag.localname] = values

    else:
        values = {}
        for child in element:
            _unmarshall(values, child)

        return values

    return res


class Response:
    SUCCESSS = 0
    UNKNOWN_ERROR = 255

    def __init__(self, response):
        """
        Construct response.

        Args:
            header (dict): Response header
            response (string): Response body
            logger (string): Response body
        """

        def get_val(res, default=None):
            return next(iter(res or []), None)

        self.root = etree.fromstring(response)

        ns = {'ns': self.root.nsmap[None]}

        compress = get_val(self.root.xpath(
            '/*/ns:Compressed/text()[1]', namespaces=ns), False)
        self.compressed = compress is not None and compress.lower() == 'true'

        self.compression_method = get_val(self.root.xpath(
            '/*/ns:CompressionMethod/text()[1]', namespaces=ns), 'RFC1952')

        # Test supported compression mehtods
        if self.compressed and self.compression_method != 'RFC1952':
            raise ValueError('Unknown compression method %s'.format(
                self.compression_method))

        self.response_text = get_val(self.root.xpath(
            '/*/ns:ResponseText/text()[1]', namespaces=ns), None)

        self.response_code = get_val(self.root.xpath(
            '/*/ns:ResponseCode/text()[1]', namespaces=ns), self.UNKNOWN_ERROR)

    def verify(self):
        """Verify signature on the response TODO """
        return self

    def deserialize(self):
        res = _unmarshall({}, self.root)
        res['ResponseCode'] = int(self.response_code)
        res['ResponseText'] = self.response_text

        if self.compressed:
            res['Content'] = gzip.decompress(base64.b64decode(res['Content']))
        elif 'Content' in res:
            res['Content'] = base64.b64decode(res['Content'])

        return res


class Request:
    """
    Request cannot be modified after signature is applied
    """

    def __init__(self, root, namespace):
        self.root = etree.Element(root, nsmap={None: namespace})
        self.data = OrderedDict()
        self._populated = False

    def __setitem__(self, key, value):
        if self._populated:
            raise AttributeError("'{0}' is a read-only".format(self.__class__))

        self.data[key] = value

    def _encode_content(self, content, compression=False):
        # Compress data
        if compression:
            content = gzip.compress(content)

        # Encode data
        return base64.b64encode(content).decode()

    def _set_optional(self, name, value):
        if value is not None:
            self[name] = value

    def sign(self, key):
        """
        Attach signature to message. After this call request should not be
        modified or the signature breaks.

        Args:
            key (pankkiyhteys.key.Key): Key
        """

        if not self._populated:
            _populate_element(self.root, self.data)
            self._populated = True

        if not key.valid():
            raise AttributeError('Key has no certificate')

        key.sign(self.root)

        return self

    def to_string(self, pretty_print=False):
        if not self._populated:
            _populate_element(self.root, self.data)
            self._populated = True

        return etree.tostring(
            self.root,
            pretty_print=pretty_print,
            xml_declaration=True,
            encoding='UTF-8')


class ApplicationRequest(Request):
    SCHEMA = "http://www.finanssiala.fi/maksujenvalitys/dokumentit/ApplicationRequest_20080918.xsd"  # noqa
    NAMESPACE = "http://bxd.fi/xmldata/"

    def __init__(self, *,
                 customer_id, timestamp, environment, software_id,
                 command=None,
                 start_date=None,
                 end_date=None,
                 status=None,
                 service_id=None,
                 file_references=None,
                 user_filename=None,
                 target_id=None,
                 execution_serial=None,
                 encryption=False,
                 compression=True,
                 amount_total=None,
                 transaction_count=None,
                 customer_extension=None,
                 file_type=None,
                 content=None):
        super().__init__('ApplicationRequest', namespace=self.NAMESPACE)

        # Order matters
        self['CustomerId'] = customer_id
        self._set_optional('Command', command)
        self['Timestamp'] = timestamp
        self._set_optional('StartDate', start_date)
        self._set_optional('EndDate', end_date)
        self._set_optional('Status', status)
        self._set_optional('ServiceId', service_id)
        self['Environment'] = environment
        self._set_optional('FileReferences', file_references)
        self._set_optional('UserFilename', user_filename)
        self._set_optional('TargetId', target_id)
        self._set_optional('ExecutionSerial', execution_serial)
        if encryption:
            raise NotImplementedError('Encryption is not implementet')
        if compression:
            self['Compression'] = True
            self['CompressionMethod'] = 'RFC1952'
        self._set_optional('AmountTotal', amount_total)
        self._set_optional('TransactionCount', transaction_count)
        self['SoftwareId'] = software_id
        self._set_optional('CustomerExtension', customer_extension)
        self._set_optional('FileType', file_type)
        if content is not None:
            self['Content'] = self._encode_content(content)


class CertApplicationRequest(Request):
    """
    Certificate service application request.

    This is most likely only Osuuspankki specific.
    """

    NAMESPACE = "http://op.fi/mlp/xmldata/"
    SCHEMA = "https://media.op.fi/media/certapplication/CertApplicationRequest_200812.xsd"  # noqa

    def __init__(self, *,
                 customer_id, timestamp, environment, software_id,
                 key=None,
                 service='MATU',
                 command=None,
                 execution_serial=None,
                 encryption=False,
                 compression=True,
                 content=None,
                 transfer_key=None,
                 serial_number=None):
        """
        Args:
            ...
            key (pankkiyhteys.key.Key, optional): RSA key that can sign
                request. Request is not signed if key is None
            service (string): Maksuliikkeen tunniste; mikä palvelun varmenne
                pyydetään. käytännössä ISSUER
            transfer_key (string, optional): Siirtoavain / jaettu salaisuus /
                salasana
            ...
        """

        super().__init__('CertApplicationRequest', namespace=self.NAMESPACE)

        # Validate transfer key
        if transfer_key is not None:
            if not luhn(int(transfer_key)):
                raise AttributeError('Invalid transfer key')

        self['CustomerId'] = customer_id
        self['Timestamp'] = timestamp
        self['Environment'] = environment
        self['SoftwareId'] = software_id
        self._set_optional('Command', command)
        self._set_optional('ExecutionSerial', execution_serial)
        if encryption:
            raise NotImplementedError('Encryption is not implementet')
        if compression:
            self['Compression'] = True
            self['CompressionMethod'] = 'RFC1952'
        self['Service'] = service
        if content is not None:
            self['Content'] = self._encode_content(content)
        self._set_optional('TransferKey', transfer_key)
        self._set_optional('SerialNumber', serial_number)

        if key is not None:
            self.sign(key)
