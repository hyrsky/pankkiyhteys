/**
 * @file Various helpers for processing xml.
 */

import * as xpath from 'xpath'

import { pki, asn1, util } from 'node-forge'

/**
 * Load base64 encoded x509 certificate
 */
export function X509ToCertificate(data: string): pki.Certificate {
  return pki.certificateFromAsn1(asn1.fromDer(util.decode64(data)))
}

// Web service security namespaces
export const namespaces = {
  soap: 'http://schemas.xmlsoap.org/soap/envelope/',
  dsig: 'http://www.w3.org/2000/09/xmldsig#',
  wsse: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
  wsu: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
}

export const WSS_X509V3 =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
export const WSS_B64BINARY =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
export const DSIG_ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'

export function getSignatureReferences(signature: any) {
  const select = xpath.useNamespaces({
    dsig: namespaces.dsig
  })

  return select('./dsig:SignedInfo/dsig:Reference/@URI', signature).map(({ value }: any) => value)
}

/**
 * Test if given element is xml root element
 */
export function isRootElement(element: any) {
  return element.documentElement !== undefined
}

/**
 * Ensure that given xml element is included in the signature.
 *
 * This function DOES NOT check validity of the signature.
 *
 * If given element is a root node the document must be signed with
 * http://www.w3.org/2000/09/xmldsig#enveloped-signature.
 *
 * @param element xml element to test or root node
 * @param signature xml signature element
 */
export function isElementSigned(element: any, signature: any): boolean {
  const select = xpath.useNamespaces({
    dsig: namespaces.dsig,
    wsse: namespaces.wsse
  })

  if (isRootElement(element)) {
    // Whole document must be included in the signature with xmldsig#enveloped-signature
    const attribute = select(
      "./dsig:SignedInfo/dsig:Reference[@URI='']/dsig:Transforms/dsig:Transform/@Algorithm",
      signature,
      true
    )

    return attribute !== undefined && (attribute as any).value === DSIG_ENVELOPED_SIGNATURE
  } else {
    // Get reference ids whitout leading '#'
    const references = getSignatureReferences(signature).map(value => value.substr(1))

    for (let i = 0; i < element.attributes.length; i++) {
      const { localName, value } = element.attributes[i]

      if (localName.toLowerCase() === 'id' && references.includes(value)) {
        return true
      }
    }

    // Signature doesn't contain reference to element.
    return false
  }
}

/**
 * Get xmldsig Signature element from document.
 *
 * @param document xml document
 */
export function getSoapSignature(document: any): any {
  const select = xpath.useNamespaces({
    soap: namespaces.soap,
    dsig: namespaces.dsig,
    wsse: namespaces.wsse
  })

  return select('/soap:Envelope/soap:Header/wsse:Security/dsig:Signature', document, true)
}

/**
 * Get certificate soap envelope
 *
 * @param signature signature element inside soap envelope
 */
export function getSoapCertificate(signature: any): pki.Certificate {
  const select = xpath.useNamespaces({
    dsig: namespaces.dsig,
    wsse: namespaces.wsse
  })

  // Get uri to binary security token.
  const uri = select(
    'substring(./dsig:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/@URI, 2)',
    signature
  )

  // Get certificate from BinarySecurityToken
  const { data } = xpath.select(
    `//*[@*[local-name(.)='Id']='${uri}']/text()`,
    signature.ownerDocument,
    true
  ) as any

  return X509ToCertificate(data)
}
