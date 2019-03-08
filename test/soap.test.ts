import SoapClient from '../src/soap'

import TrustStore, { Key, sign, verifySignature } from '../src/trust'
import * as request from 'request-promise-native'
import * as fs from 'fs'
import * as path from 'path'
import * as xpath from 'xpath'
import * as xml from '../src/xml'
import { DOMParser } from 'xmldom'

// Mock network requests
jest.mock('request-promise-native')

// Disable console.log
console.log = jest.fn()

const mockedRequest = request as jest.Mocked<typeof request>

function read(file: string) {
  return fs.readFileSync(path.join(__dirname, file), 'utf8')
}

describe('Test soap base class', () => {
  const soap = read('./data/GetFilesResponse.xml')

  beforeEach(() => {
    mockedRequest.post.mockClear()
  })

  it('Test network error', async () => {
    const client = new SoapClient()

    mockedRequest.post.mockResolvedValueOnce(Promise.reject({ error: 'Hello ' }))

    const result = client.makeSoapRequest('example.com', { hello: 'world' })

    await expect(result).rejects.toBeTruthy()
    expect(mockedRequest.post).toHaveBeenCalledTimes(1)
  })

  it('Test unsigned request', async () => {
    const client = new SoapClient()

    mockedRequest.post.mockResolvedValueOnce(Promise.resolve(soap) as any)

    const result = await client.makeSoapRequest('example.com', { hello: 'world' })

    // Expect soap request to return data in soap body.
    expect(mockedRequest.post).toHaveBeenCalledTimes(1)
    expect(result.localName).toEqual('downloadFileListout')
  })

  it('Test signed request', async () => {
    const privateKey = read('./data/key.pem')
    const certificate = read('./data/certificate.pem')
    const key = new Key(privateKey, certificate)

    const client = new SoapClient()
    const trustStore = {
      isCertificateTrusted: jest.fn().mockResolvedValueOnce(true)
    }

    mockedRequest.post.mockResolvedValueOnce(Promise.resolve(soap) as any)

    // Make the request
    const result = await client.makeSoapRequest('example.com', {}, key, trustStore as any)

    // Parse body passed to request library
    expect(mockedRequest.post).toHaveBeenCalledTimes(1)
    const { body } = mockedRequest.post.mock.calls[0][1] as any
    const doc = new DOMParser().parseFromString(body)
    const signature = xml.getSoapSignature(doc)

    // Posted xml should verify
    expect(verifySignature(body, signature, key.certificate)).toEqual(true)
  })

  it('Test invalid responses', async () => {
    const privateKey = read('./data/key.pem')
    const certificate = read('./data/certificate.pem')
    const key = new Key(privateKey, certificate)
    const client = new SoapClient()
    const trustStore = {
      isCertificateTrusted: jest
        .fn()
        .mockResolvedValue(true)
        .mockResolvedValueOnce(false as any)
    }

    mockedRequest.post
      .mockResolvedValueOnce(soap as any)
      .mockResolvedValueOnce(soap.replace('dFzMCWwrCexUidjRmZ71XR0nDqiK/sPV', 'broken') as any)
      .mockResolvedValueOnce(soap.replace('Id="_5002"', 'Id="not-signed"') as any)

    // Make the requests
    const certNotTrusted = client.makeSoapRequest('example.com', {}, key, trustStore as any)
    const invalidSignature = client.makeSoapRequest('example.com', {}, key, trustStore as any)
    const bodyNotSigned = client.makeSoapRequest('example.com', {}, key, trustStore as any)

    await expect(certNotTrusted).rejects.toBeTruthy()
    await expect(invalidSignature).rejects.toBeTruthy()
    await expect(bodyNotSigned).rejects.toBeTruthy()
  })
})
