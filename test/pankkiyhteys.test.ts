import { OsuuspankkiCertService, Osuuspankki } from '../src/pankkiyhteys'
import { Environment } from '../src/application'
import TrustStore, { Key } from '../src/trust'
import { readFile, createCertificate, forgeToKey } from './utils'

import { DOMParser } from 'xmldom'
import { namespaces } from '../src/xml'
import * as xpath from 'xpath'
import * as path from 'path'

describe('Test osuuspankki client', () => {
  let key!: Key
  let getFiles: any

  beforeAll(async () => {
    const [privateKey, certificate] = await Promise.all([
      readFile('data/key.pem'),
      readFile('data/certificate.pem')
    ])

    key = new Key(privateKey, certificate)

    const getFilesMsg = new DOMParser().parseFromString(await readFile('data/GetFilesResponse.xml'))
    getFiles = select('/soap:Envelope/soap:Body/*', getFilesMsg, true)
  })

  const select = xpath.useNamespaces({ soap: namespaces.soap })

  test('Test cert service', async () => {
    const serviceCertsXML = await readFile('data/ServiceCertificatesResponse.xml')
    const serviceCertsDocument = new DOMParser().parseFromString(serviceCertsXML)
    const serviceCertsBody = select('/soap:Envelope/soap:Body/*', serviceCertsDocument, true)

    const certService = new OsuuspankkiCertService('test-username', Environment.TEST)
    const trustStore = {
      addIntermediary: jest.fn(),
      isCertificateTrusted: jest.fn().mockResolvedValueOnce(true)
    }

    certService.makeSoapRequest = jest.fn().mockResolvedValueOnce(serviceCertsBody)

    // Do work
    await certService.addIntermediaryCertificates(trustStore as any)

    // Expectations
    expect(trustStore.addIntermediary).toBeCalled()
  })

  test('Verifying request should trigger loading new certificates.', async () => {
    const client = new Osuuspankki('test-username', key, 'EN', Environment.TEST)

    client.trustStore.useDiskCache = false
    client.makeSoapRequest = jest.fn().mockResolvedValueOnce(getFiles)
    client.certService.addIntermediaryCertificates = jest
      .fn()
      .mockImplementation((trustStore: TrustStore) => {
        expect(trustStore).toEqual(client.trustStore)
      })

    // key certificate was not in the list of added certificates so this should fail.
    await expect(client.getFileList()).rejects.toBeTruthy()

    expect.assertions(2)
  })

  test('Should return list of files.', async () => {
    const client = new Osuuspankki('test-username', key, 'EN', Environment.TEST)

    client.trustStore.isCertificateTrusted = jest.fn().mockResolvedValueOnce(true)
    client.makeSoapRequest = jest.fn().mockResolvedValueOnce(getFiles)
    client.certService.addIntermediaryCertificates = jest
      .fn()
      .mockRejectedValueOnce('Should not happen')

    await expect(client.getFileList()).resolves.toBeTruthy()
  })

  test('Should get certificate from request', async () => {
    const getCertDom = new DOMParser().parseFromString(
      await readFile('data/GetCertificateResponse.xml')
    )
    const getCert = select('/soap:Envelope/soap:Body/*', getCertDom, true)
    const client = new Osuuspankki('test-username', key, 'EN', Environment.TEST)

    // No network requests - return example data.
    client.makeSoapRequest = jest.fn().mockResolvedValueOnce(getCert)

    // Don't validate certificate
    client.verifyRequestCallback = jest.fn().mockResolvedValueOnce(true)
    client.trustStore.isCertificateTrusted = jest.fn().mockResolvedValueOnce(true)
    client.certService.addIntermediaryCertificates = jest
      .fn()
      .mockRejectedValueOnce('Should not happen')

    const newKey = forgeToKey(await createCertificate('Application'))

    // Should always generate new private key when calling getCertificate.
    // Real API would just return existing certificate.
    await expect(client.getCertificate(newKey.privateKey)).resolves.toBeTruthy()
  })
})
