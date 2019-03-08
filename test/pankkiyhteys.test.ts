import { OsuuspankkiCertService, Osuuspankki } from '../src/pankkiyhteys'
import { Environment } from '../src/application'
import TrustStore, { Key } from '../src/trust'

import { DOMParser } from 'xmldom'
import { namespaces } from '../src/xml'
import * as xpath from 'xpath'
import * as path from 'path'
import * as fs from 'fs'

function read(file: string) {
  return fs.readFileSync(path.join(__dirname, file), 'utf8')
}

describe('Test osuuspankki client', () => {
  const select = xpath.useNamespaces({ soap: namespaces.soap })
  const privateKey = read('./data/key.pem')
  const certificate = read('./data/certificate.pem')
  const key = new Key(privateKey, certificate)

  const serviceCertsXML = read('./data/ServiceCertificatesResponse.xml')
  const serviceCertsDocument = new DOMParser().parseFromString(serviceCertsXML)
  const serviceCertsBody = select('/soap:Envelope/soap:Body/*', serviceCertsDocument, true)

  const getFilesXML = read('./data/GetFilesResponse.xml')
  const getFilesDocument = new DOMParser().parseFromString(getFilesXML)
  const getFilesBody = select('/soap:Envelope/soap:Body/*', getFilesDocument, true)

  it('Test cert service', async () => {
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

  it('Verifying request should trigger loading new certificates.', async () => {
    const client = new Osuuspankki('test-username', key, 'EN', Environment.TEST)

    client.trustStore.useDiskCache = false
    client.makeSoapRequest = jest.fn().mockResolvedValueOnce(getFilesBody)
    client.certService.addIntermediaryCertificates = jest
      .fn()
      .mockImplementation((trustStore: TrustStore) => {
        expect(trustStore).toEqual(client.trustStore)
      })

    // key certificate was not in the list of added certificates so this should fail.
    await expect(client.getFileList()).rejects.toBeTruthy()

    expect.assertions(2)
  })

  it('Should return list of files.', async () => {
    const client = new Osuuspankki('test-username', key, 'EN', Environment.TEST)

    client.trustStore.isCertificateTrusted = jest.fn().mockResolvedValueOnce(true)
    client.makeSoapRequest = jest.fn().mockResolvedValueOnce(getFilesBody)
    client.certService.addIntermediaryCertificates = jest
      .fn()
      .mockRejectedValueOnce('Should not happen')

    await expect(client.getFileList()).resolves.toBeTruthy()
  })
})
