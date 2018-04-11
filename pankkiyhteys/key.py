"""
Crypto module

This module encapsulates usage of keys and encryption
primitives required by web services.

Examples:
    Generating new key and get certificate

        >>> client = pankkiyhteys.Client(...)
        >>> key = pankkiyhteys.Key.generate()
        >>> key = pankkiyhteys.certify(key, client, '1234567890123456')

    Renew certificate that is about to expire

        >>> client = pankkiyhteys.client(...)
        >>> key = pankkiyhteys.Key(...)
        >>> if key.valid() and key.valid_duration < datetime.timedelta(days=60)
                key = pankkiyhteys.key.certify(key, client)

    Save key and certificate to files

        >>> with open('key.pem', 'wb') as keyfile,
                    open('cert.pem', 'wb') as certfile:
                keyfile.write(key.private_key())
                certfile.write(key.certificate())

Todo:
    * Certificate chain validation in CertificateHandler
      https://stackoverflow.com/a/49282746
"""

from datetime import datetime, timedelta, timezone

import base64
import logging
import hashlib
import xmlsec
import codecs

import urllib.request
import urllib.error

from lxml import etree

from OpenSSL import crypto

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

WSS_BASE = 'http://docs.oasis-open.org/wss/2004/01/'

BASE64B = WSS_BASE + 'oasis-200401-wss-soap-message-security-1.0#Base64Binary'
X509TOKEN = WSS_BASE + 'oasis-200401-wss-x509-token-profile-1.0#X509v3'

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
            key (bytes|file): RSA private key in PEM format
            cert (bytes|file, optional): X509 certificate in DER format
            password (bytes, optional): Encrypted private key password

        Raises
            Exception: If the RSA key is not supported
            ValueError: If the PEM data could not be decoded successfully or
                if the key is not RSA key.
            TypeError: If a password was given and the private key was not
                encrypted. Or if the key was encrypted but no password was
                supplied.
            cryptography.exceptions.UnsupportedAlgorithm: If the serialized
                key is of a type that is not supported by the backend or if
                the key is encrypted with a symmetric cipher that is not
                supported by the backend.
        """

        self.logger = logging.getLogger(__name__)

        if hasattr(key, 'read'):
            key = key.read()

        if not isinstance(key, asymmetric.rsa.RSAPrivateKey):
            # Load key from bytes, assume PEM encoded
            key = serialization.load_pem_private_key(key, password,
                                                     default_backend())

            # PEM files could contain DSA or elliptic curve keys
            if not isinstance(key, asymmetric.rsa.RSAPrivateKey):
                raise ValueError(str(type(key)) + ' is not RSA key')

            # Banks might support larger keys(?) and if
            # not now then maybe in the future
            if key.key_size < RSA_KEY_SIZE:
                raise ValueError('Key size is not supported')

        self._private_key = key

        # Create xmlsec key
        self.sign_key = xmlsec.Key.from_memory(self.private_key(),
                                               xmlsec.KeyFormat.PEM)

        if cert is None:
            # Certificate can be None if the program just created the
            # private key and is about to create certificate signing request
            self._cert = None
        elif isinstance(cert, x509.Certificate):
            self._cert = cert
        else:
            if hasattr(cert, 'read'):
                cert = cert.read()

            # Load x509 PEM certificate from bytes
            self._cert = x509.load_pem_x509_certificate(
                cert, default_backend())

        # Add certificate to xmlsec key
        if self.valid():
            self.sign_key.load_cert_from_memory(self.certificate(),
                                                xmlsec.KeyFormat.PEM)

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
            encryption_algorithm = serialization.BestAvailableEncryption(
                password)

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
        Check if the certificate is considered valid. This does not check if
        the certificate is revoked.

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


def load_certificate(data):
    """Load der encoded certificate into pem encoded bytes"""
    return (x509.load_der_x509_certificate(data, default_backend())
                .public_bytes(encoding=serialization.Encoding.PEM))


class CertificateHandler(MemorySignature):
    """
    Custom wsse handler for zeep.

    Check if certificate in the request is trusted and also correctly insert
    timestamp to wsse header.

    TODO
        * This class could benefit from caching
          -> cache revocation list to dist
    """

    def __init__(self):
        self.key = None
        self.crl = None
        self.crl_url = None

    def _log_cert(self, message, cert):
        cert = cert.to_cryptography()
        fingerprint = cert.fingerprint(HASH_FUNCTION())
        fingerprint = '0x{}'.format(codecs.encode(fingerprint, 'hex').decode())
        common_name = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)[0].value

        self.logger.info(message, common_name, fingerprint)

    def init(self, key, ca, crl_url, logger):
        self.key = key
        self.ca = crypto.load_certificate(crypto.FILETYPE_PEM, ca)
        self.intermediaries = []
        self.crl_url = crl_url

        self.logger = logger
        self._log_cert("Trusting CA \"%s\" <%s>", self.ca)

    def add_intermediary(self, cert_buffer, *,
                         cert_encoding=crypto.FILETYPE_ASN1):
        if self.should_refresh():
            try:
                self.refresh_revocation_list()
            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                raise ValueError('Unable to verify intermediary certificate')

        try:
            # Warning validation of certificate chains is not properly
            # supported by any major python crypto library.
            # See: https://stackoverflow.com/a/49282746
            store = crypto.X509Store()
            store.add_cert(self.ca)
            store.add_crl(crypto.CRL.from_cryptography(self.crl))

            cert = crypto.load_certificate(cert_encoding, cert_buffer)
            store_ctx = crypto.X509StoreContext(store, cert)
            store_ctx.verify_certificate()

            # Intermediary passed validation
            self._log_cert("Trusting intermediary \"%s\" <%s>", cert)
            self.intermediaries.append(cert)

        # Exception is thrown when verification fails
        except crypto.X509StoreContextError as e:
            raise ValueError('Unable to verify intermediary certificate')

    def apply(self, envelope, headers):
        """Override zeep.wsse.signature.MemorySignature.apply"""
        sign(envelope, self.key)

        return envelope, headers

    def verify(self, envelope):
        """Override zeep.wsse.signature.MemorySignature.verify"""

        cert = self.get_certificate(envelope)
        if cert is None or not self.is_cert_trusted(cert):
            raise ValueError('Could not verify certificate')

        verify(envelope, cert, encoding=xmlsec.constants.KeyDataFormatCertDer)

        return envelope

    def get_certificate(self, envelope):
        """Find and return certificate from the XML document

        Return:
            bytes: DER encoded bytes. None if no certificate found.
        """

        def get_keyinfo(security):
            keyinfo = security.xpath(
                "./ds:Signature/ds:KeyInfo",
                namespaces={
                    'ds': xmlsec.constants.DSigNs,
                })

            if len(keyinfo) != 1:
                return None

            return keyinfo[0]

        def get_security(envelope):
            security = envelope.xpath(
                './/wsse:Security', namespaces={'wsse': ns.WSSE})

            if len(security) != 1:
                return None

            return security[0]

        # FIXME: ApplicationReqeust doesn't have security header
        security = get_security(envelope)
        if security is None:
            return None

        keyinfo = get_keyinfo(security)
        if keyinfo is None:
            return None

        reference = keyinfo.xpath(
            "./wsse:SecurityTokenReference/wsse:Reference",
            namespaces={
                'ds': xmlsec.constants.DSigNs,
                'wsse': ns.WSSE,
            })

        if len(reference) == 1:
            # Certificate is in BinarySecurityToken element.

            bst = security.xpath(
                ".//wsse:BinarySecurityToken[@wsu:Id = '{}']".format(
                    reference[0].attrib['URI'].lstrip('#')),
                namespaces={
                    'wsse': ns.WSSE,
                    'wsu': ns.WSU
                })

            if len(bst) == 1:
                bst = bst[0]
                encoding = bst.attrib.get('EncodingType')
                value_type = bst.attrib.get('ValueType')

                # Only base64 encoded x509 is supported
                if encoding == BASE64B and value_type == X509TOKEN:
                    return base64.b64decode(bst.text)

        """
        elif len(reference) == 0:
            # Certificate is in X509Certificate element
            certificate = keyinfo.xpath(
                "//ds:X509Certificate",
                namespaces={'ds': xmlsec.constants.DSigNs})

            if len(certificate) == 1:
                return certificate[0].text
        """

        return None

    def should_refresh(self):
        return self.crl is None or self.crl.next_update > datetime.now()

    def refresh_revocation_list(self):
        """Refresh certificate revocation list"""
        self.logger.info("Refreshing revocation list")
        with urllib.request.urlopen(self.crl_url) as response:
            self.crl = x509.load_der_x509_crl(response.read(),
                                              default_backend())

    def is_cert_trusted(self, cert_buffer, *,
                        cert_encoding=crypto.FILETYPE_ASN1):
        """Return true if certificate is considered trusted

        Certificate is trusted if it is signed by trusted certificate
        authority and it is not expired or revoked.

        Args:
            cert_buffer (bytes): DER encoded certificate
        """
        # If revocation list should be updated
        if self.should_refresh():
            try:
                self.refresh_revocation_list()
            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                return False

        try:
            # Warning validation of certificate chains is not properly
            # supported by any major python crypto library.
            # See: https://stackoverflow.com/a/49282746
            store = crypto.X509Store()
            store.add_cert(self.ca)
            store.add_crl(crypto.CRL.from_cryptography(self.crl))

            # Intermediaries here are validated beforehand
            for intermediary in self.intermediaries:
                store.add_cert(intermediary)

            cert = crypto.load_certificate(cert_encoding, cert_buffer)
            store_ctx = crypto.X509StoreContext(store, cert)
            store_ctx.verify_certificate()

            return True

        # Exception is thrown when verification fails
        except crypto.X509StoreContextError as e:
            return False


"""
Code below this is adapted from zeep wsse module. Their code didn't add
the required timestamp header.
"""


def _add_timestamp(node):
    timestamp = etree.Element(
        etree.QName(ns.WSU, 'Timestamp'), nsmap={'wsu': ns.WSU})

    created = datetime.now(timezone.utc)
    expires = (created + timedelta(hours=1))
    created = created.isoformat(timespec='seconds').replace('+00:00', 'Z')
    expires = expires.isoformat(timespec='seconds').replace('+00:00', 'Z')

    etree.SubElement(timestamp, etree.QName(ns.WSU, 'Created')).text = created
    etree.SubElement(timestamp, etree.QName(ns.WSU, 'Expires')).text = expires

    node.append(timestamp)


def _create_binary_security_token(key):
    bst = etree.Element(
        etree.QName(ns.WSSE, 'BinarySecurityToken'),
        ValueType=X509TOKEN,
        EncodingType=BASE64B,
        nsmap={'wsu': ns.WSU})

    ensure_id(bst)

    bst.text = base64.b64encode(
        key.certificate(encoding=serialization.Encoding.DER))

    return bst


def verify(envelope, cert, *, encoding=xmlsec.constants.KeyDataFormatCertPem):
    """Verify WS-Security signature on XML document with given cert.

    No certificate validation is performed

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

    key = xmlsec.Key.from_memory(cert, encoding)

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
    security_token = etree.SubElement(key_info,
                                      etree.QName(ns.WSSE,
                                                  'SecurityTokenReference'))
    etree.SubElement(security_token, etree.QName(ns.WSSE, 'Reference'),
                     ValueType=X509TOKEN,
                     URI='#' + bst.get(etree.QName(ns.WSU, 'Id')))

    soap_env = detect_soap_env(envelope)
    security = get_security_header(envelope)
    security.set(etree.QName(soap_env, 'mustUnderstand'), '1')

    # Add timestamp
    _add_timestamp(security)

    # Insert the Signature node in the wsse:Security header.
    security.append(bst)
    security.append(signature)

    ctx = xmlsec.SignatureContext()
    ctx.key = key.sign_key

    _sign_node(ctx, signature, security.find(etree.QName(ns.WSU, 'Timestamp')))
    _sign_node(ctx, signature, envelope.find(etree.QName(soap_env, 'Body')))

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
