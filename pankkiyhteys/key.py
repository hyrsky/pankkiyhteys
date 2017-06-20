"""
Crypto module

This module encapsulates usage of keys and encryption
primitives required by web services.

Examples:
    Generating new key and get certificate

        client = pankkiyhteys.Client(...)
        key = pankkiyhteys.Key.generate()
        key = pankkiyhteys.certify(key, client, '1234567890123456')

    Renew certificate that is about to expire

        client = pankkiyhteys.client(...)
        key = pankkiyhteys.Key(...)
        if key.valid() and key.valid_duration < datetime.timedelta(days=60)
            key = pankkiyhteys.key.certify(key, client)

    Save key and certificate to files

        with open('key.pem', 'wb') as keyfile, open('cert.pem', 'wb') as certfile:
            keyfile.write(key.private_key())
            certfile.write(key.certificate())

Todo:
    * Implement pankkiyhteys.key.certify()
    * Change all Exceptions to some other exception type
    * Make unit tests
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, asymmetric, serialization
from cryptography.hazmat.backends import default_backend

from datetime import datetime

import signxml

RSA_KEY_SIZE = 2048
"""
Size of accepted RSA key. This is chosen from accepted
key size in Web services documentation.
"""

HASH_FUNCTION = hashes.SHA1
"""
Hash primitive to use in cryptographinc operations.
This is chosen form accepted hash functions in Web services
documentation
"""

class Key:
    """
    Web services messages require signature from signed X509 certificate
    aquired from the bank. This class handles storage and usage of the
    key and the certificate.
    """

    @classmethod
    def generate(cls):
        """
        Generate new RSA key

        Returns:
            pankkiyhteys.key.Key
        """
        return cls(asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        ))

    def __init__(self, key, cert=None, *, password=None):
        """
        Construct key object

        Args:
            key (bytes): RSA private key in PEM format
            cert (bytes, optional): X509 certificate in PEM format
            password (bytes, optional): Encrypted private key password

        Raises
            Exception: If the RSA key is not supported
            ValueError: If the PEM data could not be decoded successfully or
                if the key is not RSA key.
            TypeError: If a password was given and the private key was not
                encrypted. Or if the key was encrypted but no password was
                supplied.
            cryptography.exceptions.UnsupportedAlgorithm: If the serialized
                key is of a type that is not supported by the backend or if the key
                is encrypted with a symmetric cipher that is not supported by the
                backend.
        """

        if not isinstance(key, asymmetric.rsa.RSAPrivateKey):
            # Load key from bytes, assume PEM encoded
            key = serialization.load_pem_private_key(key, password, default_backend())

            # PEM files could contain DSA or elliptic curve keys
            if not isinstance(key, asymmetric.rsa.RSAPrivateKey):
                raise ValueError(str(type(key)) + ' is not RSA key')

            # Banks might support larger keys(?) and if
            # not now then maybe in the future
            if key.key_size < RSA_KEY_SIZE:
                raise ValueError('Key size is not supported')

        self._private_key = key

        if cert is None:
            # Certificate can be None if the program just created the
            # private key and is about to create certificate signing request
            self._cert = None
        elif isinstance(cert, x509.Certificate):
            self._cert = cert
        else:
            # Load x509 PEM certificate from bytes
            self._cert = x509.load_pem_x509_certificate(
                cert, default_backend()
            )

        # Initialize XML Signer with correct algorithm
        self.signer = signxml.XMLSigner(
            signature_algorithm='rsa-sha1',
            digest_algorithm='sha1'
        )

    def private_key(self, password=None):
        """
        Get private key bytes

        Args:
            password (bytes): Private key password

        Return:
            bytes: PEM encoded bytes containing the private key. If
                password was supplied the private key is encrypted
        """

        if password is None:
            encryption_algorithm = serialization.NoEncryption()
        else:
            encryption_algorithm = serialization.BestAvailableEncryption(password)

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

    def certificate(self):
        """
        Get certificate bytes

        Raises:
            AttributeError: if key has no certificate

        Return:
            bytes: PEM encoded bytes containing the X509 certificate
        """
        if self._cert is None:
            raise AttributeError('Key has no certificate')

        return self._cert.public_bytes(encoding=serialization.Encoding.PEM)

    def valid(self):
        """
        Check if the certificate is considered valid. This does
        not check if the certificate is revoked.

        Returns:
            bool: True if library considers this certificate valid.
        """

        if self._cert is None:
            return False

        return (self._cert.not_valid_before < datetime.utcnow() <
                self._cert.not_valid_after)

    @property
    def valid_duration(self):
        """
        Get duration to certificate expiration

        Returns:
            Timedelta representing the duration until end of the
            validity period for the certificate

        Raises:
            AttributeError: if key has no certificate
        """

        if self._cert is None:
            raise AttributeError('Key has no certificate')

        return self._cert.not_valid_after - datetime.utcnow()

    def sign(self, request):
        """
        Sign request with this key

        Raises:
            Exception: If key has no certificate
        """
        return self.signer.sign(request, key=self._private_key, cert=self.certificate())

    def generate_csr(self, client, hash=hashes.SHA1):
        """
        Generate X509 certificate signing request

        Returns:
            bytes: certificate in der format
        """

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Identity details required by the bank
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, client.country),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, client.username),
        ])).sign(self._private_key, HASH_FUNCTION(), default_backend())

        return csr.public_bytes(serialization.Encoding.DER)
