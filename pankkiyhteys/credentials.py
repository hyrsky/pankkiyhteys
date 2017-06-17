"""
Crypto module

This module encapsulates usage of keys and encryption
primitives required by web services.

Examples:
    Generating new key and get certificate

        client = pankkiyhteys.client(...)
        key = pankkiyhteys.credentials.generate()
        key = pankkiyhteys.credentials.certify(key, client, '1234567890123456')

    Renew certificate that is about to expire

        client = pankkiyhteys.client(...)
        key = pankkiyhteys.Key(...)
        if key.valid() and key.valid_duration < datetime.timedelta(days=60)
            key = pankkiyhteys.credentials.certify(key, client)

    Save key and certificate to files

        with open('key.pem', 'wb') as keyfile, open('cert.pem', 'wb') as certfile:
            keyfile.write(key.private_key())
            certfile.write(key.certificate())

Todo:
    * Implement pankkiyhteys.credentials.certify()
    * Change all Exceptions to some other exception type
    * Make unit tests
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, asymmetric, serialization
from cryptography.hazmat.backends import default_backend

from datetime import datetime

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

class Key(object):
    """
    Web services requires signed X509 certificate to encrypt and sign messages
    to the bank. This class abstracts storing and usage of the key and certificate
    """

    def __init__(self, key, cert=None, *, password=None):
        """
        Construct key object

        Args:
            key (bytes): RSA private key in PEM format
            cert (bytes, optional): X509 certificate in PEM format
            password (bytes, optional): Encrypted private key password

        Raises
            Exception: If the RSA key is not supported
            ValueError: If the PEM data could not be decrypted or if its
                structure could not be decoded successfully.
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
            key = serialization.load_pem_private_key(key, password, default_backend)

            # PEM files could contain DSA or elliptic curve keys
            if not isinstance(key, asymmetric.rsa.RSAPrivateKey):
                raise Exception('Key ' + str(type(key)) + ' is not supported')

            # Banks might support larger keys(?) and if
            # not now then maybe in the future
            if key.key_size() < RSA_KEY_SIZE:
                raise Exception('Key size is not supported')

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

        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)

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

    def generate_csr(self, client, hash=hashes.SHA1):
        """
        Generate X509 certificate signing request

        Returns:
            cryptography.x509.CertificateSigningRequest
        """

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Identity details required by the bank
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, client.country),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, client.username),
        ])).sign(self._private_key, hash, default_backend())

        return csr

def generate():
    """
    Generate new RSA key

    Returns:
        pankkiyhteys.credentials.Key
    """
    return Key(asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    ))

def certify(key, client, *, transfer_key=None):
    """
    Request signed certificate from bank key service

    Args:
        key pankkiyhteys.credentials.Key: The key to certify.
        transfer_key (str): 16 digit one-time key required to prove identity when
            requesting the first certificate. User must register with the bank to
            get this key. Transfer key must be used if no valid certificate is
            available, othervise the certificate can used to to prove identity.

    Raises:
        Exception: Unable to load key
        Exception: Communication error

    Returns:
        pankkiyhteys.credentials.Key: Certified key object. Make sure to
            save the certificate afterwards
    """

    def luhn(n):
        """Luhn mod 10 checksum by Hans Peter Luhn (1896-1964)"""
        sum = 0
        num_digits = len(n)
        oddeven = num_digits & 1

        for count in range(0, num_digits):
            digit = int(n[count])

            if not ((n & 1) ^ oddeven):
                digit = digit * 2
            if digit > 9:
                digit = digit - 9

            sum = sum + digit

        return (sum % 10) == 0

    cert_service = client.cert_service()

    # Generate certificate signing request
    csr = key.generate_csr(client).public_bytes(serialization.Encoding.PEM)

    # Build application request
    request = {}

    if transfer_key is not None:
        # Validate transfer key with luhn algorithm
        if not luhn(transfer_key):
            raise Exception('Invalid transfer key')

        request['TransferKey'] = transfer_key

    # Sign certificate request with existing key
    if key.valid():
        request['foo'] = 'bar'
        pass
    else:
        raise Exception('')

    crt = cert_service.get_certificate(csr)

    return Key()
