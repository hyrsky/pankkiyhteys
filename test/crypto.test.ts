import { verifySignature, sign, Key } from '../src/trust'
import { readFile } from './utils'

import * as path from 'path'
import * as xpath from 'xpath'

import { DOMParser } from 'xmldom'
import { namespaces, getSoapSignature } from '../src/xml'

let config = {} as { [key: string]: any }

beforeAll(async () => {
  const [privateKey, certificate] = await Promise.all([
    await readFile('data/key.pem'),
    await readFile('data/certificate.pem')
  ])

  config = {
    privateKey,
    certificate,
    key: new Key(privateKey, certificate)
  }
})

it('Test verify xml signature', async () => {
  const signedSoap = await readFile('data/soap-signed.xml')
  const document = new DOMParser().parseFromString(signedSoap)
  const signature = getSoapSignature(document)

  expect(verifySignature(signedSoap, signature, config.key.certificate)).toEqual(true)
})

it('Test sign xml', async () => {
  const signedXml = sign(await readFile('data/request.xml'), config.key, [])
  const document = new DOMParser().parseFromString(signedXml)

  const select = xpath.useNamespaces({
    dsig: namespaces.dsig
  })

  const digest = select('//dsig:SignedInfo/dsig:Reference/dsig:DigestValue/text()', document, true)

  const signatureValue = select('//dsig:Signature/dsig:SignatureValue/text()', document, true)

  // Precomputed value
  expect(digest).not.toBeNull()

  if (digest) {
    expect(digest.toString()).toEqual('7qBb+2dONa5AbfIYi12E+X3KAYQ=')
  }
})

it('verify(sign(msg)) === truthy', async () => {
  const soap = await readFile('data/soap.xml')
  const signedXml = sign(
    soap,
    config.key,
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

  expect(verifySignature(signedXml, signature, config.key.certificate)).toEqual(true)
})
