import TrustStore, { Key } from '../src/trust'
import { readFile, createCertificate, forgeToKey } from './utils'

import file from '../src/file'
import * as path from 'path'

import { pki } from 'node-forge'

// Mock file module
jest.mock('../src/file')
const mockedFile = file as jest.Mocked<typeof file>

let config = {} as { [key: string]: any }

/**
 * Generate some test data beforehand
 *
 */
beforeAll(async () => {
  const [privateKey, certificate] = await Promise.all([
    await readFile('data/key.pem'),
    await readFile('data/certificate.pem')
  ])

  // Certificate chain
  const ca = await createCertificate('CA')
  const intermediary = await createCertificate('Intermediary', ca)
  const application = await createCertificate('Application', intermediary, { expiring: true })

  config = {
    privateKey,
    certificate,
    key: new Key(privateKey, certificate),
    ca,
    intermediary,
    application
  }
})

beforeEach(() => {
  mockedFile.readdir.mockClear()
  mockedFile.readFile.mockClear()
})

test('Test detect expiring certificates', async () => {
  const notExpiring = forgeToKey(config.ca)
  const expiring = forgeToKey(config.application)

  expect(notExpiring.isAboutToExpire()).toEqual(false)
  expect(expiring.isAboutToExpire()).toEqual(true)
})

test('Test TrustStore verify', async () => {
  const spy = jest.fn()
  const store = new TrustStore([config.ca.cert], spy, false)

  store.addIntermediary(config.intermediary.cert)

  // Intermediary was added
  expect(store.getIntermediaries()).not.toEqual([])

  expect(await store.isCertificateTrusted(config.application.cert)).toEqual(true)

  // Trust store should not have requested issued the callback.
  expect(spy).not.toBeCalled()
})

test('Test TrustStore callback/cache', async () => {
  const spy = jest.fn()
  const filename = 'test-file.pem'
  const store = new TrustStore([], spy)

  // Disk cache returns one file which should be untrusted and not added to the system.
  mockedFile.readdir.mockResolvedValueOnce([filename] as any)
  mockedFile.readFile.mockResolvedValueOnce(config.key.getCertificate())

  // Test with no loading option
  expect(await store.isCertificateTrusted(config.key.certificate, true)).toEqual(false)

  // Should not attempt to load anything.
  expect(mockedFile.readdir).not.toHaveBeenCalled()
  expect(mockedFile.readFile).not.toHaveBeenCalled()
  expect(spy).not.toHaveBeenCalled()

  // Try again - this time allow loading intermediaries
  expect(await store.isCertificateTrusted(config.key.certificate)).toEqual(false)

  // Trust store requested new certificates with a callback.
  expect(spy).toBeCalled()

  // Disk cache attempted to access file.
  expect(mockedFile.readFile).toHaveBeenCalled()

  // Intermediary from disk was not added because it was not trusted.
  expect(store.getIntermediaries()).toEqual([])
})

test('Test TrustStore cache', async () => {
  const spy = jest.fn()
  const filename = 'test-file.pem'
  const store = new TrustStore([config.ca.cert], spy)

  // Disk cache returns no files.
  mockedFile.readdir.mockResolvedValueOnce([filename] as any)
  mockedFile.readFile.mockResolvedValueOnce(pki.certificateToPem(config.intermediary.cert) as any)

  const trusted = await store.isCertificateTrusted(config.application.cert)

  // Certificate cannot be validated.
  expect(trusted).toEqual(true)

  // Trust store requested new certificates with a callback.
  expect(spy).not.toHaveBeenCalled()
})

test('Test adding intermediary certificates', async () => {
  const spy = jest.fn()
  const store = new TrustStore([config.ca.cert], spy, false)

  // Should not add untrusted certificate (no CA)
  store.addIntermediary(config.key.certificate)
  expect(store.getIntermediaries()).toEqual([])

  // Should not add untrusted certificate (expired)
  store.addIntermediary((await createCertificate('Expired', config.ca, { expired: true })).cert)
  expect(store.getIntermediaries()).toEqual([])

  // Should add valid certificate (trusted)
  store.addIntermediary(config.intermediary.cert)
  expect(store.getIntermediaries().length).toEqual(1)
})

test('Test adding intermediary certificates to disk cache', done => {
  const spy = jest.fn()
  const store = new TrustStore([config.ca.cert], spy, true)
  const mockImplementation: any = (fname: string, data: string) => {
    expect(data).toEqual(pki.certificateToPem(config.intermediary.cert))

    done()

    // Writing to disk fails
    return Promise.reject('Error')
  }

  store.addIntermediary(config.intermediary.cert)

  // This should not throw even when the disk operation fails
  mockedFile.writeFile.mockImplementationOnce(mockImplementation)

  expect.assertions(1)
})
