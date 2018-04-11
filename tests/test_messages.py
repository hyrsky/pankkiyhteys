import unittest

from lxml import etree
from datetime import datetime

import pankkiyhteys.messages

APPLICATION_RESPONE = """<?xml version="1.0" encoding="UTF-8"?>
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
</ApplicationResponse>""".encode()


class RequestTestSuite(unittest.TestCase):
    pass


class ResponseTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.envelope = etree.fromstring(
            APPLICATION_RESPONE, parser=etree.XMLParser(
                remove_blank_text=True))

        cls.header = {
            'SenderId': '1234567890',
            'RequestId': '18000000000',
            'Timestamp': datetime(2018, 4, 11, 2, 6, 39, 186000),
            'ResponseCode': '00',
            'ResponseText': 'OK.'
        }

    def test_parse_response(self):
        request = pankkiyhteys.messages.Response(self.header,
                                                 APPLICATION_RESPONE)
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
        """TODO"""
