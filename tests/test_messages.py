import unittest

from lxml import etree
from datetime import datetime

import pankkiyhteys.messages

APP_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<ApplicationResponse xmlns="http://bxd.fi/xmldata/" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#">
  <CustomerId>1000061998</CustomerId>
  <Timestamp>2018-04-11T00:12:53.377+03:00</Timestamp>
  <ResponseCode>00</ResponseCode>
  <ResponseText>OK.</ResponseText>
  <FileDescriptors>
    <FileDescriptor>
      <FileReference>258963370</FileReference>
      <TargetId>MLP</TargetId>
      <UserFilename>rj-258963370</UserFilename>
      <FileType>INFO</FileType>
      <FileTimestamp>2018-03-20T00:00:00+02:00</FileTimestamp>
      <Status>DLD</Status>
      <ForwardedTimestamp>2018-03-20T00:00:00+02:00</ForwardedTimestamp>
    </FileDescriptor>
  </FileDescriptors>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  </Signature>
</ApplicationResponse>""".encode()  # noqa

COMPRESSED_APP_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<ApplicationResponse xmlns="http://bxd.fi/xmldata/" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#">
  <CustomerId>1234567890</CustomerId>
  <Timestamp>2018-04-11T05:18:58.371+03:00</Timestamp>
  <ResponseCode>00</ResponseCode>
  <ResponseText>OK.</ResponseText>
  <Compressed>true</Compressed>
  <CompressionMethod>RFC1952</CompressionMethod>
  <Content>H4sIAAAAAAAAAJWQQU7DQAxF95VyBx+gREmhAnXHBgmFqoiGBUtLsYQ7zkxVeyLlPrlJL4bTIsSCDUuP/3//e7Y5W1IIKVJgElajCMbCyYy482FgisbqO6OQUscci0WxuC3vylVVPwBKQJf1OXVJLc/yf+HQrdnIEGffyYwdk1iESpiDmp+3w192SBGSSDZADuibvucI96tqCT2H8/SLHkeDJ44YVRlljiMNWYXZHBLygDno5ZQLSI3hEhGUHVhf67Tfx5AIQjxPYRw85FrIK80mPU8s4wgUI7oK4wZem91b2z5vH5v9OxgyXOfdvt3tyxn7wu4ypi7ZBj5ObKPewMH/BoNmbxjoiDKQ37mEY/4soaqrCqp1va6LxRfq57oTxQEAAA==</Content>
</ApplicationResponse>""".encode()  # noqa


class RequestTestSuite(unittest.TestCase):
    pass


class ResponseTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def test_parse_response(self):
        request = pankkiyhteys.messages.Response(APP_RESPONSE)
        result = request.deserialize()

        # ResponseCode should be converted to integer
        self.assertEqual(result['ResponseCode'], 0)
        self.assertEqual(result['ResponseText'], 'OK.')

        assert isinstance(result['FileDescriptors'], list)
        self.assertDictEqual(result['FileDescriptors'][0], {
            'FileReference': '258963370',
            'TargetId': 'MLP',
            'UserFilename': 'rj-258963370',
            'FileType': 'INFO',
            'FileTimestamp': '2018-03-20T00:00:00+02:00',
            'Status': 'DLD',
            'ForwardedTimestamp': '2018-03-20T00:00:00+02:00'})

    def test_compression(self):
        """Test that library is able to correctly decompress content"""

        request = pankkiyhteys.messages.Response(COMPRESSED_APP_RESPONSE)
        result = request.deserialize()

        # ResponseCode should be converted to integer
        self.assertEqual(result['ResponseCode'], 0)
        self.assertEqual(result['ResponseText'], 'OK.')

        self.assertTrue(result['Content'].decode().startswith(
            'Muutos konekielisten tiliotteiden vientiselitekoodiin'))

        print(result)
