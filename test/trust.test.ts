import TrustStore, { verifySignature, sign, Key } from '../src/trust'

import * as file from '../src/file'
import * as fs from 'fs'
import * as path from 'path'
import * as xpath from 'xpath'

import { DOMParser } from 'xmldom'
import { pki } from 'node-forge'
import { namespaces, getSoapSignature } from '../src/xml'

function read(file: string) {
  return fs.readFileSync(path.join(__dirname, file), 'utf8')
}

// Mock file module
jest.mock('../src/file')

const mockedFile = file as jest.Mocked<typeof file>

/** Create certificate signed with another key */
function createCertificate(
  name: string,
  signee?: { privateKey: pki.rsa.PrivateKey; certificate: pki.Certificate },
  errors: { expired?: boolean; notSigned?: boolean } = {}
) {
  const keys = pki.rsa.generateKeyPair(1024)
  const cert = pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  // Generate expired certificate
  if (errors.expired) {
    cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 5)
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 4)
  }

  const attrsIssuer = [
    {
      name: 'commonName',
      value: 'example.com'
    },
    {
      name: 'organizationName',
      value: name
    }
  ]

  cert.setSubject(attrsIssuer)

  if (!signee) {
    // self-sign certificate
    cert.setIssuer(attrsIssuer)

    if (!errors.notSigned) {
      cert.sign(keys.privateKey)
    }
  } else {
    cert.setIssuer(signee.certificate.subject.attributes)

    if (!errors.notSigned) {
      cert.sign(signee.privateKey)
    }
  }

  return {
    privateKey: keys.privateKey,
    certificate: cert
  }
}

describe('Test trust module', () => {
  const privateKey = read('./data/key.pem')
  const certificate = read('./data/certificate.pem')
  const key = new Key(privateKey, certificate)

  // Certificate chain
  const ca = createCertificate('CA')
  const intermediary = createCertificate('Intermediary', ca)
  const application = createCertificate('Application', intermediary)

  beforeEach(() => {
    mockedFile.readDirectory.mockClear()
    mockedFile.readFile.mockClear()
  })

  it('Test verify xml signature', () => {
    const signedSoap = read('./data/soap-signed.xml')
    const document = new DOMParser().parseFromString(signedSoap)
    const signature = getSoapSignature(document)

    expect(verifySignature(signedSoap, signature, key.certificate)).toEqual(true)
  })

  it('Test sign xml', () => {
    const signedXml = sign(read('./data/request.xml'), key, [])
    const document = new DOMParser().parseFromString(signedXml)

    const select = xpath.useNamespaces({
      dsig: namespaces.dsig
    })

    const digest = select(
      '//dsig:SignedInfo/dsig:Reference/dsig:DigestValue/text()',
      document,
      true
    ).toString()

    const signatureValue = select(
      '//dsig:Signature/dsig:SignatureValue/text()',
      document,
      true
    ).toString()

    // Precomputed value
    expect(digest).toEqual('7qBb+2dONa5AbfIYi12E+X3KAYQ=')
  })

  it('Signed document should pass verify', () => {
    const soap = read('./data/soap.xml')
    const signedXml = sign(
      soap,
      key,
      ["//*[local-name(.)='Security']/*[local-name(.)='Timestamp']"],
      {
        wssecurity: true,
        location: {
          reference: "/*/*[local-name(.)='Header']/*[local-name(.)='Security']",
          action: 'append'
        }
      }
    )

    const document = new DOMParser().parseFromString(signedXml)
    const signature = getSoapSignature(document)

    expect(verifySignature(signedXml, signature, key.certificate)).toEqual(true)
  })

  it('Test TrustStore verify', async () => {
    const spy = jest.fn()
    const store = new TrustStore([ca.certificate], spy, false)

    store.addIntermediary(intermediary.certificate)

    // Intermediary was added
    expect(store.getIntermediaries()).not.toEqual([])

    expect(await store.isCertificateTrusted(application.certificate)).toEqual(true)

    // Trust store should not have requested issued the callback.
    expect(spy).not.toBeCalled()
  })

  it('Test TrustStore callback/cache', async () => {
    const spy = jest.fn()
    const filename = 'test-file.pem'
    const store = new TrustStore([], spy)

    // Disk cache returns one file which should be untrusted and not added to the system.
    mockedFile.readDirectory.mockResolvedValueOnce([filename] as any)
    mockedFile.readFile.mockResolvedValueOnce(key.getPemCertificate() as any)

    // Test with no loading option
    expect(await store.isCertificateTrusted(key.certificate, true)).toEqual(false)

    // Should not attempt to load anything.
    expect(mockedFile.readDirectory).not.toHaveBeenCalled()
    expect(mockedFile.readFile).not.toHaveBeenCalled()
    expect(spy).not.toHaveBeenCalled()

    // Try again - this time allow loading intermediaries
    expect(await store.isCertificateTrusted(key.certificate)).toEqual(false)

    // Trust store requested new certificates with a callback.
    expect(spy).toBeCalled()

    // Disk cache attempted to access file.
    expect(mockedFile.readFile).toHaveBeenCalled()
    expect(mockedFile.readFile.mock.calls[0][0].endsWith(filename)).toEqual(true)

    // Intermediary from disk was not added because it was not trusted.
    expect(store.getIntermediaries()).toEqual([])
  })

  it('Test TrustStore cache', async () => {
    const spy = jest.fn()
    const filename = 'test-file.pem'
    const store = new TrustStore([ca.certificate], spy)

    // Disk cache returns no files.
    mockedFile.readDirectory.mockResolvedValueOnce([filename] as any)
    mockedFile.readFile.mockResolvedValueOnce(pki.certificateToPem(intermediary.certificate) as any)

    const trusted = await store.isCertificateTrusted(application.certificate)

    // Certificate cannot be validated.
    expect(trusted).toEqual(true)

    // Trust store requested new certificates with a callback.
    expect(spy).not.toHaveBeenCalled()
  })

  it('Test adding intermediary certificates', async () => {
    const spy = jest.fn()
    const store = new TrustStore([ca.certificate], spy, false)

    // Should not add untrusted certificate (no CA)
    store.addIntermediary(key.certificate)
    expect(store.getIntermediaries()).toEqual([])

    // Should not add untrusted certificate (expired)
    store.addIntermediary(createCertificate('Expired', ca, { expired: true }).certificate)
    expect(store.getIntermediaries()).toEqual([])

    // Should add valid certificate (trusted)
    store.addIntermediary(intermediary.certificate)
    expect(store.getIntermediaries().length).toEqual(1)
  })

  it('Test adding intermediary certificates to disk cache', done => {
    const spy = jest.fn()
    const store = new TrustStore([ca.certificate], spy, true)
    const mockImplementation: any = (fname: string, data: string) => {
      expect(data).toEqual(pki.certificateToPem(intermediary.certificate))

      done()

      // Writing to disk fails
      return Promise.reject('Error')
    }

    store.addIntermediary(intermediary.certificate)

    // This should not throw even when the disk operation fails
    mockedFile.writeFile.mockImplementationOnce(mockImplementation)

    expect.assertions(1)
  })
})
