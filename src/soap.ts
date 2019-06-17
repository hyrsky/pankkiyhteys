import * as request from 'request-promise-native'
import * as builder from 'xmlbuilder'
import * as xpath from 'xpath'
import createDebug from 'debug'
import { v4 as uuid } from 'uuid'
import { DOMParser } from 'xmldom'

import TrustStore, { Key, verifySignature, sign } from './trust'
import * as xml from './xml'

const debug = createDebug('pankkiyhteys')

const BINARY_SECURITY_TOKEN_ID = 'BinarySecurityToken'

export default class SoapClient {
  /**
   * Helper method to format time string.
   */
  formatTime(date: Date) {
    return date.toISOString().slice(0, -5) + 'Z'
  }

  /**
   * Helper method to add minutes to given Date object.
   *
   * If a parameter specified is outside of the expected range, set*()
   * attempts to update the date information in the Date object accordingly
   */
  addMinutes(date: Date, time: number) {
    date.setMinutes(date.getMinutes() + time)
    return date
  }

  /**
   * Generate 35 character long random request id.
   */
  requestId() {
    return uuid().substr(0, 35)
  }

  /**
   * Make soap request.
   *
   * @param url Endpoint url.
   * @param body Soap request body element.
   */
  makeSoapRequest(url: string, body: {}): Promise<any>
  makeSoapRequest(url: string, body: {}, signatureKey: Key, trustStore: TrustStore): Promise<any>

  async makeSoapRequest(url: string, body: {}, signatureKey?: Key, trustStore?: TrustStore) {
    debug('Soap request to %s', url)

    const envelope = {
      'soap:Envelope': {
        '@xmlns:soap': xml.namespaces.soap,
        'soap:Header': {},
        'soap:Body': body
      }
    }

    // Assume client wants to sign the request if key was provided.
    // Add signature to wsse:Security header.
    if (signatureKey) {
      const created = new Date()
      const expires = this.addMinutes(new Date(created.valueOf()), 30)

      envelope['soap:Envelope']['soap:Header'] = {
        'wsse:Security': {
          '@xmlns:wsse': xml.namespaces.wsse,
          '@xmlns:wsu': xml.namespaces.wsu,
          '@soap:mustUnderstand': '1',
          'wsu:Timestamp': {
            'wsu:Created': this.formatTime(created),
            'wsu:Expires': this.formatTime(expires)
          },
          'wsse:BinarySecurityToken': {
            '@wsu:Id': 'BinarySecurityToken',
            '@ValueType': xml.WSS_X509V3,
            '@EncodingType': xml.WSS_B64BINARY,
            '#text': signatureKey.getBase64Certificate()
          }
        }
      }
    }

    // Build xml string.
    let xmlBody = builder
      .create(envelope, { version: '1.0', encoding: 'UTF-8' })
      .end({ pretty: true, indent: '  ' })

    // Sign xml string if signature key was specified.
    if (signatureKey) {
      xmlBody = this.signEnvelope(xmlBody, signatureKey)
    }

    console.log('Request', xmlBody)

    return request
      .post(url, {
        body: xmlBody,
        headers: {
          'Content-Type': 'text/xml; charset=utf-8'
        }
      })
      .then(async response => {
        const select = xpath.useNamespaces({
          soap: xml.namespaces.soap,
          dsig: xml.namespaces.dsig,
          wsse: xml.namespaces.wsse
        })

        console.log('Response', response)

        const document = new DOMParser().parseFromString(response)
        const responseBody = select('/soap:Envelope/soap:Body', document, true)

        // Verify response envelope if request had signature.
        if (signatureKey) {
          // Verify xml signature. This throws if verification fails.
          await this.verifyEnvelopeSignature(response, document, trustStore!)
        }

        /**
         * @todo verify envelope signature
         * @note cert request envelopes are not signed
         */

        return responseBody.firstChild
      })
  }

  /**
   * Verify soap envelope signature
   *
   * @param body xml document
   * @param document parsed xml dom
   * @param trustStore
   *
   * @throws if signature verification fails
   */
  private async verifyEnvelopeSignature(body: string, document: any, trustStore: TrustStore) {
    const signature = xml.getSoapSignature(document)
    const certificate = xml.getSoapCertificate(signature)

    // Envelope body must be signed.
    const select = xpath.useNamespaces({
      soap: xml.namespaces.soap,
      wsu: xml.namespaces.wsu
    })

    // Body id must be signed
    if (!xml.isElementSigned(select('/soap:Envelope/soap:Body', document, true), signature)) {
      throw new Error('Envelope body is not signed')
    }

    if (!(await trustStore.isCertificateTrusted(certificate))) {
      throw new Error('Signature key is not trusted')
    }

    if (!verifySignature(body, signature, certificate)) {
      throw new Error('Signature verification failed')
    }

    return true
  }

  /**
   * Sign soap envelope
   *
   * @param xml XML envelope
   * @param key Signing key in pem format
   */
  private signEnvelope(body: string, key: Key) {
    const keyInfo = builder
      .create(
        {
          'wsse:SecurityTokenReference': {
            '@xmlns:wsse': xml.namespaces.wsse,
            'wsse:Reference': {
              '@xmlns:wsu': xml.namespaces.wsu,
              '@URI': `#${BINARY_SECURITY_TOKEN_ID}`,
              '@ValueType': xml.WSS_X509V3
            }
          }
        },
        {
          headless: true
        }
      )
      .end()

    return sign(
      body,
      key,
      [
        "/*[local-name(.)='Envelope']/*[local-name(.)='Header']/*/*[local-name(.)='Timestamp']",
        "/*[local-name(.)='Envelope']/*[local-name(.)='Body']"
      ],
      keyInfo,
      {
        wssecurity: true,
        location: {
          reference: "/*/*[local-name(.)='Header']/*[local-name(.)='Security']",
          action: 'append'
        },
        existingPrefixes: {
          wsse: xml.namespaces.wsse,
          wsu: xml.namespaces.wsu
        }
      }
    )
  }
}
