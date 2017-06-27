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

from datetime import datetime, timedelta

import base64
import logging
import hashlib
import xmlsec

from lxml import etree
from lxml.etree import QName

from zeep import ns
from zeep.utils import detect_soap_env
from zeep.wsse.signature import MemorySignature
from zeep.wsse.utils import ensure_id, get_security_header

from cryptography import x509
from cryptography.hazmat.primitives import hashes, asymmetric, serialization
from cryptography.hazmat.backends import default_backend

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

ID_ATTR = etree.QName(ns.WSU, 'Id')

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
        logger = logging.getLogger(__name__)
        key = cls(asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        ))
        logger.info('Generated private key <%s>' % key.fingerprint)
        return key

    def __init__(self, key, cert=None, *, password=None):
        """
        Construct key object

        Args:
            key (bytes): RSA private key in PEM format
            cert (bytes, optional): X509 certificate in DER format
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

        self.logger = logging.getLogger(__name__)

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

        # Create xmlsec key
        self.sign_key = xmlsec.Key.from_memory(self.private_key(), xmlsec.KeyFormat.PEM)

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

        # Add certificate to xmlsec key
        if self.valid():
            self.sign_key.load_cert_from_memory(self.certificate(), xmlsec.KeyFormat.PEM)

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

    def certificate(self, *, encoding=serialization.Encoding.PEM):
        """
        Get certificate bytes

        Args:
            encoding (serialization.Encoding):

        Raises:
            AttributeError: if key has no certificate

        Return:
            bytes: PEM encoded bytes containing the X509 certificate
        """
        if self._cert is None:
            raise AttributeError('Key has no certificate')

        return self._cert.public_bytes(encoding=encoding)

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
    def fingerprint(self):
        return hashlib.sha256(self.private_key()).hexdigest()

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

        Args:
            request (lxml.Element): XML node to sign

        Raises:
            Exception: If key has no certificate
        """

        # Create a signature template for RSA-SHA1 enveloped signature.
        signature_node = xmlsec.template.create(
            request,
            xmlsec.Transform.C14N,
            xmlsec.Transform.RSA_SHA1)

        # Create a digital signature context (no key manager is needed).
        ctx = xmlsec.SignatureContext()
        ctx.key = self.sign_key

        # Add the <ds:Reference/> node to the signature template.
        ref = xmlsec.template.add_reference(
            signature_node, xmlsec.Transform.SHA1, uri="")

        # Add the enveloped transform descriptor.
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

        # Add the <ds:KeyInfo/> and <ds:X509Data/> nodes.
        key_info = xmlsec.template.ensure_key_info(signature_node)
        xmlsec.template.add_x509_data(key_info)

        request.append(signature_node)

        # Sign the template.
        ctx.sign(signature_node)

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

def validate(data):
    """Validate xml signature"""
    return False

def load_certificate(data):
    """Load der encoded certificate into pem encoded bytes"""
    return (x509.load_der_x509_certificate(data, default_backend())
                .public_bytes(encoding=serialization.Encoding.PEM))

class SignWSSE(MemorySignature):
    """
    Zeep doesn't insert required timestamp to wsse header
    """

    def __init__(self, client):
        self.client = client

    def apply(self, envelope, headers):
        """Override zeep.wsse.signature.MemorySignature.apply"""
        sign(envelope, self.client.key)

        return envelope, headers

    def verify(self, envelope):
        """Override zeep.wsse.signature.MemorySignature.verify"""
        # TODO

        return envelope


WSS_BASE = 'http://docs.oasis-open.org/wss/2004/01/'

BASE64B = WSS_BASE + 'oasis-200401-wss-soap-message-security-1.0#Base64Binary'
X509TOKEN = WSS_BASE + 'oasis-200401-wss-x509-token-profile-1.0#X509v3'

"""
Code below this is adapted from zeep wsse module. Their code
didn't work correctly for me so I had to patch it

Todo:
"""

def _add_timestamp(node):
    timestamp = etree.Element(QName(ns.WSU, 'Timestamp'), nsmap={'wsu': ns.WSU})

    created = datetime.utcnow().replace(microsecond=0)
    expires = (created + timedelta(hours=1)).isoformat() + 'Z'
    created = created.isoformat() + 'Z'

    etree.SubElement(timestamp, QName(ns.WSU, 'Created')).text = created
    etree.SubElement(timestamp, QName(ns.WSU, 'Expires')).text = expires

    node.append(timestamp)

def _create_binary_security_token(key):
    bst = etree.Element(
        QName(ns.WSSE, 'BinarySecurityToken'),
        ValueType=X509TOKEN,
        EncodingType=BASE64B,
        nsmap={'wsu': ns.WSU})

    ensure_id(bst)

    bst.text = base64.b64encode(
        key.certificate(encoding=serialization.Encoding.DER))

    return bst

def verify(envelope, cert):
    """
    Verify WS-Security signature on given SOAP envelope with given cert.

    Raises:
        SignatureValidationFailed: on failure, silent on success.
    """
    signature = xmlsec.tree.find_node(envelope, xmlsec.constants.NodeSignature)

    ctx = xmlsec.SignatureContext()

    # Find each signed element and register its ID with the signing context.
    refs = signature.xpath('ds:SignedInfo/ds:Reference',
                           namespaces={'ds': xmlsec.constants.DSigNs})
    for ref in refs:
        # Get the reference URI and cut off the initial '#'
        referenced_id = ref.get('URI')[1:]
        referenced = envelope.xpath(
            "//*[@wsu:Id='%s']" % referenced_id,
            namespaces={'wsu': ns.WSU},
        )[0]
        ctx.register_id(referenced, 'Id', ns.WSU)

    key = xmlsec.Key.from_memory(cert, xmlsec.KeyFormat.CERT_PEM, None)

    ctx.key = key
    ctx.verify(signature)

def sign(envelope, key):
    """
    Add WS-Security signature on given SOAP envelope with given key.

    Raises:
        SignatureValidationFailed: on failure, silent on success.
    """
    # Create the Signature node.
    signature = xmlsec.template.create(
        envelope,
        xmlsec.Transform.EXCL_C14N,
        xmlsec.Transform.RSA_SHA1,
    )

    bst = _create_binary_security_token(key)

    # Add a KeyInfo node with SecurityTokenReference child to the Signature.
    # Add Reference to BinarySecurityToken to SecurityTokenReference
    key_info = xmlsec.template.ensure_key_info(signature)
    security_token = etree.SubElement(key_info, QName(ns.WSSE, 'SecurityTokenReference'))
    etree.SubElement(security_token, QName(ns.WSSE, 'Reference'),
                     ValueType=X509TOKEN,
                     URI='#' + bst.get(QName(ns.WSU, 'Id')))

    soap_env = detect_soap_env(envelope)
    security = get_security_header(envelope)
    security.set(QName(soap_env, 'mustUnderstand'), '1')

    # Add timestamp
    _add_timestamp(security)

    # Insert the Signature node in the wsse:Security header.
    security.append(bst)
    security.append(signature)

    ctx = xmlsec.SignatureContext()
    ctx.key = key.sign_key

    _sign_node(ctx, signature, security.find(QName(ns.WSU, 'Timestamp')))
    _sign_node(ctx, signature, envelope.find(QName(soap_env, 'Body')))

    # Perform the actual signing.
    ctx.sign(signature)

def _sign_node(ctx, signature, target):
    """Add sig for ``target`` in ``signature`` node, using ``ctx`` context.
    Doesn't actually perform the signing; ``ctx.sign(signature)`` should be
    called later to do that.
    Adds a Reference node to the signature with URI attribute pointing to the
    target node, and registers the target node's ID so XMLSec will be able to
    find the target node by ID when it signs.
    """

    # Ensure the target node has a wsu:Id attribute and get its value.
    node_id = ensure_id(target)

    # Unlike HTML, XML doesn't have a single standardized Id. WSSE suggests the
    # use of the wsu:Id attribute for this purpose, but XMLSec doesn't
    # understand that natively. So for XMLSec to be able to find the referenced
    # node by id, we have to tell xmlsec about it using the register_id method.
    ctx.register_id(target, 'Id', ns.WSU)

    # Add reference to signature with URI attribute pointing to that ID.
    ref = xmlsec.template.add_reference(
        signature, xmlsec.Transform.SHA1, uri='#' + node_id)

    # This is an XML normalization transform which will be performed on the
    # target node contents before signing. This ensures that changes to
    # irrelevant whitespace, attribute ordering, etc won't invalidate the
    # signature.
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
