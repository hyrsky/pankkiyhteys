import unittest
import random

import pankkiyhteys.banks as banks

class ServiceTestSuite(unittest.TestCase):
    def mock_client(self):
        class TestClient:
            username = '1234567890'
            country = 'FI'
            bank = random.choice(list(banks.Bank))
            environment = random.choice(list(banks.Environment))

        return TestClient()

    def test_factory(self):
        invalid_client = self.mock_client()
        invalid_client.bank = 'invalid bank'

        with self.assertRaises(NotImplementedError):
            banks.WebService.factory(object(), invalid_client)
        with self.assertRaises(NotImplementedError):
            banks.CertService.factory(object(), invalid_client)

        service = banks.CertService.factory(object(), self.mock_client())
        assert isinstance(service, banks.CertService)

        service = banks.WebService.factory(object(), self.mock_client())
        assert isinstance(service, banks.WebService)

class OsuuspankkiTestSuite(unittest.TestCase):
    pass
