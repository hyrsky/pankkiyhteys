/**
 * @file Test application request helper functions
 */

import * as application from '../src/application'
import TrustStore from '../src/trust'

import * as xpath from 'xpath'
import * as fs from 'fs'
import * as path from 'path'

import { namespaces } from '../src/xml'
import { DOMParser } from 'xmldom'

function read(file: string) {
  return fs.readFileSync(path.join(__dirname, file), 'utf8')
}

describe('Test xml module', () => {
  const select = xpath.useNamespaces({ soap: namespaces.soap })
  const soap = new DOMParser().parseFromString(read('./data/ServiceCertificatesResponse.xml'))
  const certApplicationResponse = read('./data/CertApplicationResponse.xml')

  it('Test parseResponseHeader', () => {
    const response = (select('/soap:Envelope/soap:Body', soap, true) as any).firstChild
    const header = application.parseResponseHeader(response)

    expect(header.ResponseCode).toEqual('00')
  })

  it('Test parseApplicationResponse', async () => {
    const response = (select('/soap:Envelope/soap:Body', soap, true) as any).firstChild
    const parsed = await application.parseApplicationResponse(response, (xml, dom) => {
      expect(typeof xml).toBe('string')
    })

    const {
      CertApplicationResponse: { ResponseCode }
    } = parsed

    expect(ResponseCode).toEqual(0)
    expect.assertions(2)
  })

  it('Test verifyApplicationRequestSignature - valid signature', async () => {
    const parsed = new DOMParser().parseFromString(certApplicationResponse)

    // Not testing trustStore here -> mock it.
    const trustStore = new TrustStore([], () => {
      throw new Error('Should not be happen')
    })

    trustStore.isCertificateTrusted = jest.fn().mockReturnValueOnce(true)

    // Should not throw
    await application.verifyApplicationRequestSignature(certApplicationResponse, parsed, trustStore)

    // Should test signature validity
    expect(trustStore.isCertificateTrusted).toBeCalled()

    trustStore.isCertificateTrusted = jest.fn().mockReturnValueOnce(false)

    // Should throw
    await expect(
      application.verifyApplicationRequestSignature(certApplicationResponse, parsed, trustStore)
    ).rejects.toBeTruthy()
  })

  it('Test verifyApplicationRequestSignature - invalid signature', async () => {
    // Break signature
    const invalidSignature = certApplicationResponse.replace(
      'QK91ft78aDhyFle2RdrpyADxoOGOFarwV6bQzyLPo+8FZfqqiJ57RhluaSW7bU0pwxC9ed6xlpv7',
      'test'
    )

    const parsed = new DOMParser().parseFromString(invalidSignature)

    // Not testing trustStore here -> mock it.
    const trustStore = new TrustStore([], () => {
      throw new Error('Should not be happen')
    })

    trustStore.isCertificateTrusted = jest.fn().mockReturnValueOnce(true)

    // Should throw
    await expect(
      application.verifyApplicationRequestSignature(invalidSignature, parsed, trustStore)
    ).rejects.toBeTruthy()
  })

  it('Test verifyApplicationRequestSignature - element not signed', async () => {
    // Break transform
    const invalidSignature = certApplicationResponse.replace(
      'Reference URI=""',
      'Reference URI="#not-root-element"'
    )

    const parsed = new DOMParser().parseFromString(invalidSignature)
    const trustStore = {
      isCertificateTrusted: jest.fn().mockResolvedValueOnce(true)
    }

    const result = application.verifyApplicationRequestSignature(
      invalidSignature,
      parsed,
      trustStore as any
    )

    // Should throw
    await expect(result).rejects.toBeTruthy()
  })
})
