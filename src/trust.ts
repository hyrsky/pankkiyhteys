import { tmpdir } from 'os'
import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
import * as path from 'path'
import * as xpath from 'xpath'
import createDebug from 'debug'

import file from './file'
import { SignedXml, ComputeSignatureOptions } from 'xml-crypto'
import { pki, md, asn1, util } from 'node-forge'

const debug = createDebug('pankkiyhteys')

/** Pem encoded string containing X509 key. */
export type X509Pem = string

type XMLElement = ReturnType<xpath.XPathSelect>

/** Callback that loads new intermediary certificates. */
type LoadCertificatesCallback = (trustStore: TrustStore) => Promise<void>

/** Directory name for intermediary cache directory. */
const TMP_DIRNAME = 'pankkiyhteys'

/**
 * Key object contains RSA private and public key pair.
 *
 * This class also offers convinience methods for converting between file
 * formats. (wrappers for node-forge and nodejs crypto modules)
 */
export class Key {
  privateKey: string
  certificate: pki.Certificate

  constructor(key: string, cert: string) {
    this.privateKey = key
    this.certificate = pki.certificateFromPem(cert)

    if (this.isAboutToExpire()) {
      debug('warning: certificate is about to expire')
    }
  }

  /**
   * Return true if certificate is about to expire (less than a month remaining).
   */
  isAboutToExpire() {
    const dateToCheck = new Date()
    dateToCheck.setMonth(dateToCheck.getMonth() + 1)
    return this.expires() < dateToCheck
  }

  /**
   * Return certificate expiration date
   */
  expires(): Date {
    return this.certificate.validity.notAfter
  }

  /**
   * Get PEM encoded certificate
   */
  getCertificate() {
    return pki.certificateToPem(this.certificate)
  }

  /**
   * Get PEM encoded private key
   */
  getPrivateKey() {
    return this.privateKey
  }

  getBase64Certificate() {
    return util.encode64(asn1.toDer(pki.certificateToAsn1(this.certificate)).getBytes())
  }

  /**
   * Generate new rsa private key.
   */
  static async generateKey() {
    const modulusLength = 2048
    debug(`Generating ${modulusLength}-bit key-pair...`)

    const { publicKey, privateKey } = await promisify(generateKeyPair)('rsa', {
      modulusLength,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    })

    return privateKey
  }
}

interface SignExtraOptions {
  wssecurity?: boolean
  canonicalizationAlgorithm?:
    | 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    | 'http://www.w3.org/2001/10/xml-exc-c14n#'
}

type SignOptions = ComputeSignatureOptions & SignExtraOptions

/**
 * Convert certificate signing request to base64 encoded der
 *
 * @param csr
 */
function encodeSigningRequest(csr: pki.Certificate) {
  return util.encode64(asn1.toDer(pki.certificationRequestToAsn1(csr)).getBytes())
}

/**
 * Create certificate signing request from pem encoded private key.
 *
 * @return base der formatted csr.
 */
export function generateSigningRequest(
  privateKeyPem: string,
  commonName: string,
  countryName: string
) {
  const privateKey = pki.privateKeyFromPem(privateKeyPem)
  const publicKey = pki.rsa.setPublicKey((privateKey as any).n, (privateKey as any).e)

  const csr = pki.createCertificationRequest()
  csr.publicKey = publicKey
  csr.setSubject([
    {
      name: 'commonName',
      value: commonName
    },
    {
      name: 'countryName',
      value: countryName
    }
  ])
  csr.sign(privateKey)

  debug('Certification request (CSR) created.')
  return encodeSigningRequest(csr)
}

/**
 * Sign xml document
 *
 * @param xml xml document
 * @param references xpath selectors to elements that will be signed
 * @param key pem encoded key that the document will be signed with
 * @param keyInfo optional xml string for KeyInfo element
 *
 * @return signed xml string
 */
export function sign(
  xml: string,
  key: Key,
  references: string[],
  keyInfoOrOptions?: string | SignOptions,
  options?: SignOptions
) {
  let keyInfo: string | undefined = undefined

  if (typeof keyInfoOrOptions !== 'string') {
    options = keyInfoOrOptions
  } else {
    keyInfo = keyInfoOrOptions
  }

  let wssecurity: string | undefined = undefined
  if (options && options.wssecurity) {
    wssecurity = 'wssecurity'
  }

  // Optionally use wssecurity namespace.
  const signer = new SignedXml(wssecurity)

  // [optional] one of the supported canonicalization algorithms.
  if (options && options.canonicalizationAlgorithm) {
    signer.canonicalizationAlgorithm = options.canonicalizationAlgorithm
  }

  if (references.length > 0) {
    // Add references.
    for (const reference of references) {
      signer.addReference(reference)
    }
  } else {
    // Or use enveloped signature on root element.
    signer.addReference(
      '/*',
      ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
      undefined,
      undefined,
      undefined,
      undefined,
      true
    )
  }

  signer.signingKey = key.privateKey
  signer.keyInfoProvider = {
    getKeyInfo(signingKey: any, prefix: any) {
      // Optional keyInfo (or use autogenerated)
      if (keyInfo) {
        return keyInfo
      }

      prefix = prefix || ''
      prefix = prefix ? prefix + ':' : prefix

      return (
        `<${prefix}X509Data>` +
        `<${prefix}X509Certificate>${key.getBase64Certificate()}</${prefix}X509Certificate>` +
        `</${prefix}X509Data>`
      )
    }
  }

  signer.computeSignature(xml, options)

  return signer.getSignedXml()
}

/**
 * Verify xml signature
 *
 * This does not check if the key itself is trusted.
 *
 * In order to protect from some attacks caller must check the content they
 * want to use is the one that has been signed.
 *
 * @param xml xml document
 * @param signature signature xml element
 * @param key key that the document should be signed with
 */
export function verifySignature(xml: string, signature: XMLElement, key: pki.Certificate) {
  const signer = new SignedXml()
  signer.loadSignature(signature)
  signer.keyInfoProvider = {
    getKey: () => pki.certificateToPem(key)
  }

  return signer.checkSignature(xml)
}

export default class TrustStore {
  protected readonly tmpDir = path.join(tmpdir(), TMP_DIRNAME)
  protected loadCertificates: LoadCertificatesCallback
  protected caStore: pki.CAStore

  /** Internally cached intermediary certificates */
  protected intermediaries: Map<string, pki.Certificate> = new Map()

  /** Enable / disable caching intermediary certificates to disk */
  useDiskCache: boolean

  /**
   * Constructor
   *
   * @param caCerts List of pem encoded x509 certificate authority certificates.
   * @param loadCertificates Callback that loads intermediary certificates.
   * @param useDiskCache Enable / disable intermediary disk cache.
   */
  constructor(
    caCerts: Array<X509Pem | pki.Certificate>,
    loadCertificates: LoadCertificatesCallback,
    useDiskCache = true
  ) {
    this.caStore = pki.createCaStore()
    this.loadCertificates = loadCertificates
    this.useDiskCache = useDiskCache

    for (const cert of caCerts) {
      this.caStore.addCertificate(cert)
    }
  }

  /**
   * Test if given certificate is trusted.
   *
   * @param certificate Certificate to test.
   * @param noLoading Don't attempt to load new intermediary certificates.
   */
  async isCertificateTrusted(certificate: pki.Certificate, noLoading = false): Promise<boolean> {
    if (!this.verifyCertificate(certificate)) {
      if (noLoading) {
        return false
      }

      if (this.useDiskCache) {
        // Verification failed: try to read certificates from disk if flag is set.
        await this.loadCachedCertificates()

        // In best case all necessary certificates are found from disk.
        // If not give client change to present new certificates with a callback.
        if (this.verifyCertificate(certificate)) {
          return true
        }
      }

      // Try again.
      debug('Loading new certificates')

      // Request new certificates callback.
      // This might cause network requests.
      await this.loadCertificates(this)

      if (!this.verifyCertificate(certificate)) {
        return false
      }
    }

    return true
  }

  /**
   * Add intermediary certificate to internal cache.
   *
   * @param certificate Certificate to add.
   * @param cacheToDisk Also cache this certificate to disk.
   */
  addIntermediary(certificate: pki.Certificate, cacheToDisk: boolean = this.useDiskCache) {
    const { value: commonName } = certificate.subject.getField('CN')

    try {
      // Only accept certificates that are trusted by a certificate authority.
      if (pki.verifyCertificateChain(this.caStore, [certificate])) {
        debug('Intermediary certificate "%s" added', commonName)

        // Add to list of accepted intermediaries overwriting existing certificate if any.
        this.intermediaries.set(commonName, certificate)

        if (cacheToDisk) {
          // Cache certificate to disk asynchronously.
          // It is not critical whether this fails or not.
          setImmediate(() => this.cacheToDisk(certificate))
        }
      }
    } catch (err) {
      /**
       * Cached directory might be riddled with certificates from multiple runs
       * of this program to different endpoints. We cannot fail fatally because
       * we encountered unknown intermediarry.
       */
      debug('Intermediary certificate "%s" is not trusted - ignoring', commonName)
    }
  }

  /**
   * Get currently cached intermediary certificates
   */
  getIntermediaries() {
    return Array.from(this.intermediaries.values())
  }

  /**
   * Internal verify certificate.
   *
   * @param certificate
   */
  private verifyCertificate(certificate: pki.Certificate): boolean {
    const { value: commonName } = certificate.issuer.getField('CN')

    const intermediary = this.intermediaries.get(commonName)

    // Intermediary not found
    if (!intermediary) {
      return false
    }

    try {
      return pki.verifyCertificateChain(this.caStore, [certificate, intermediary])
    } catch {
      return false
    }
  }

  /**
   * Load certificates cached to disk.
   */
  private async loadCachedCertificates() {
    try {
      await file.mkdir(this.tmpDir)
    } catch (err: any) {
      // Ignore error if directory exists.
      if (err.code !== 'EEXIST') {
        throw err
      }
    }

    const files = await file.readdir(this.tmpDir)
    const certs = await Promise.all(
      files.map(filename =>
        file
          .readFile(path.join(this.tmpDir, filename), 'utf8')
          .then(data => pki.certificateFromPem(data))
          .catch(err => debug(`Error loading ${filename} ${err}`))
      )
    )

    if (certs.length > 0) {
      debug('Loading cached certificates from %s', this.tmpDir)
    }

    // Load found certificate to internal cache.
    for (const cert of certs.filter(cert => cert) as pki.Certificate[]) {
      this.addIntermediary(cert, false)
    }
  }

  private cacheToDisk(certificate: pki.Certificate) {
    const fingerprint = md.sha1
      .create()
      .update(asn1.toDer(pki.certificateToAsn1(certificate)).getBytes())
      .digest()
      .toHex()

    const filename = path.join(this.tmpDir, `${fingerprint}.pem`)

    // Ignore errors
    file.writeFile(filename, pki.certificateToPem(certificate)).catch(err => debug(err))
  }
}
