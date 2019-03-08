/**
 * @file Test xml helper functions
 */

import * as xml from '../src/xml'
import * as xpath from 'xpath'
import * as fs from 'fs'
import * as path from 'path'
import * as builder from 'xmlbuilder'

import { DOMParser } from 'xmldom'

const SoapReferences = ['#timestamp', '#body']

function read(file: string) {
  return fs.readFileSync(path.join(__dirname, file), 'utf8')
}

function build(xmlSpec: any) {
  return new DOMParser().parseFromString(builder.create(xmlSpec).end())
}

describe('Test xml module', () => {
  const soap = new DOMParser().parseFromString(read('./data/soap-signed.xml'))

  it('Test isRootElement', () => {
    const document = build({
      Envelope: {
        '@xmlns': xml.namespaces.soap,
        Header: {},
        Body: {}
      }
    })

    expect(xml.isRootElement(document)).toEqual(true)
    expect(xml.isRootElement(document.documentElement)).toEqual(false)
  })

  it('Test getSoapSignature', () => {
    expect(xml.getSoapSignature(soap).localName).toEqual('Signature')
  })

  it('Test getSignatureReferences', () => {
    const sig = xml.getSoapSignature(soap)

    expect(xml.getSignatureReferences(sig)).toEqual(expect.arrayContaining(SoapReferences))
  })

  it('Test getSoapCertificate', () => {
    const sig = xml.getSoapSignature(soap)
    const key = xml.getSoapCertificate(sig)

    expect(key).toBeDefined()
  })

  it('Test isElementSigned with references', () => {
    const sig = xml.getSoapSignature(soap)
    const body = xpath.select("/*[local-name()='Envelope']/*[local-name()='Body']", soap, true)
    const header = xpath.select("/*[local-name()='Envelope']/*[local-name()='Header']", soap, true)

    // Body element should be signed
    expect(xml.isElementSigned(body, sig)).toEqual(true)

    // Header should not be signed
    expect(xml.isElementSigned(header, sig)).toEqual(false)
  })

  it('Test isElementSigned with enveloped signature', () => {
    const valid = build({
      root: {
        Signature: {
          '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
          SignedInfo: {
            Reference: [
              {
                '@URI': '',
                Transforms: {
                  Transform: {
                    '@Algorithm': 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
                  }
                }
              }
            ]
          }
        }
      }
    })

    const signature = xpath.select("/*/*[local-name()='Signature']", valid, true)

    // Body element should be signed
    expect(xml.isElementSigned(valid, signature)).toEqual(true)
  })

  it('Test isElementSigned with invalid enveloped signature', () => {
    const invalid = build({
      root: {
        Signature: {
          '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
          SignedInfo: {
            Reference: [
              {
                '@URI': '#my-element',
                Transforms: {
                  Transform: {
                    '@Algorithm': 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
                  }
                }
              }
            ]
          }
        }
      }
    })

    const signature = xpath.select("/*/*[local-name()='Signature']", invalid, true)

    // Body element should be signed
    expect(xml.isElementSigned(invalid, signature)).toEqual(false)
  })

  it('Test isElementSigned with invalid signature algorithm', () => {
    const invalid = build({
      root: {
        Signature: {
          '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
          SignedInfo: {
            Reference: [
              {
                '@URI': '',
                Transforms: {
                  Transform: {
                    '@Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#'
                  }
                }
              }
            ]
          }
        }
      }
    })

    const signature = xpath.select("/*/*[local-name()='Signature']", invalid, true)

    // Body element should be signed
    expect(xml.isElementSigned(invalid, signature)).toEqual(false)
  })
})
