/**
 * @file Main entrypoint
 */

import * as builder from 'xmlbuilder'
import * as xpath from 'xpath'
import createDebug from 'debug'

import SoapClient from './soap'
import TrustStore, { generateSigningRequest, sign, Key } from './trust'
import { X509ToCertificate } from './xml'
import * as app from './application'

// Certificate authority
import { OPPohjola, OPPohjolaTest } from './cacerts/OP-Pohjola'
import { pki } from 'node-forge'

const debug = createDebug('pankkiyhteys')

interface FileDescriptor {
  FileReference: string
  TargetId: string
  UserFilename: string
  ParentFileReference: string
  FileType: string
  FileTimestamp: string
  Status: 'NEW' | 'WFP' | 'DLD'
}

interface FileListResponse {
  ApplicationResponse: {
    FileDescriptors: FileDescriptor[]
  }
}

interface CertApplicationRequest {
  '@xmlns': string
  /** Customer id issued by provider. */
  CustomerId: string
  /** Request timestamp in ISO 8601. */
  Timestamp: string
  /** Application environment string. */
  Environment: string
  /** User-agent string. */
  SoftwareId: string
  /** Service indentifier */
  Service: string
  /** pkcs#10 request */
  Content?: string
  /** Shared secret */
  TransferKey?: string
}

export { Key } from './trust'

export class OsuuspankkiCertService extends SoapClient implements app.CertService {
  username: string
  environment: app.Environment

  constructor(username: string, environment: app.Environment = app.Environment.PRODUCTION) {
    super()

    this.username = username
    this.environment = environment
  }

  static getEndpoint(environment: app.Environment) {
    return {
      [app.Environment.PRODUCTION]: 'https://wsk.op.fi/services/OPCertificateService',
      [app.Environment.TEST]: 'https://wsk.asiakastesti.op.fi/services/OPCertificateService'
    }[environment]
  }

  getRootCA() {
    return {
      [app.Environment.PRODUCTION]: [OPPohjola],
      [app.Environment.TEST]: [OPPohjolaTest]
    }[this.environment]
  }

  async addIntermediaryCertificates(trustStore: TrustStore) {
    debug('getServiceCertificates')

    const request: CertApplicationRequest = {
      '@xmlns': 'http://op.fi/mlp/xmldata/',
      CustomerId: this.username,
      Timestamp: this.formatTime(new Date()),
      Environment: this.environment,
      SoftwareId: app.VERSION_STRING,
      Service: 'MATU'
    }

    // Convert application request xml.
    const requestXml = builder
      .create({ CertApplicationRequest: request })
      .end({ pretty: true, indent: '  ' })

    // Cert service envelopes are not signed.
    const response = await this.makeSoapRequest(
      OsuuspankkiCertService.getEndpoint(this.environment),
      {
        getServiceCertificatesin: {
          '@xmlns': 'http://mlp.op.fi/OPCertificateService',
          RequestHeader: {
            SenderId: this.username,
            RequestId: this.requestId(),
            Timestamp: this.formatTime(new Date())
          },
          ApplicationRequest: Buffer.from(requestXml).toString('base64')
        }
      }
    )

    // Use preprocess callback that adds certificates to trust store.
    // Otherwise we might not have intermediary certificates before signature validation.
    await app.parseApplicationResponse(response, async (xml, document) => {
      const certificates = xpath.select(
        "/*/*[local-name()='Certificates']/*[local-name()='Certificate']",
        document
      )

      for (const cert of certificates as Array<any>) {
        if (cert) {
          const format = xpath.select("./*[local-name()='CertificateFormat']/text()", cert, true)
          const data = xpath.select("./*[local-name()='Certificate']/text()", cert, true)

          // @todo: test format?

          if (data) {
            trustStore.addIntermediary(X509ToCertificate(data.toString()))
          }
        }
      }

      /**
       * Service certificates is special case because we need to parse request
       * before verifying the signature if intermediery certificate cache is not
       * warm.
       */

      // Verify signature after intermediaries have been added to trust store.
      // Prevent recursion loop with noLoading parameter.
      await app.verifyApplicationRequestSignature(xml, document, trustStore, true)
    })
  }
}

export class Osuuspankki extends app.Client {
  certService: OsuuspankkiCertService

  constructor(
    username: string,
    key: Key,
    language: app.Language,
    environment = app.Environment.PRODUCTION
  ) {
    const certService = new OsuuspankkiCertService(username, environment)
    const endpoint = Osuuspankki.getEndpoint(environment)
    const bic = 'OKOYFIHH'

    super(username, key, language, bic, endpoint, certService, environment)

    this.certService = certService
  }

  private static getEndpoint(environment: app.Environment) {
    return {
      [app.Environment.PRODUCTION]: 'https://wsk.op.fi/services/CorporateFileService',
      [app.Environment.TEST]: 'https://wsk.asiakastesti.op.fi/services/CorporateFileService'
    }[environment]
  }

  /**
   * Get new certificate from cert service.
   *
   * Private must have following conditions:
   *   * Modulus lenth = 2048
   *   * If key already has signed certificate the current certificate will be returned instead.
   *
   * Client must save the private key to persistent storage before calling this method.
   *
   * @todo: replace currently used key
   *
   * @param privateKey RSA private key (pem)
   */
  async getCertificate(privateKey: string) {
    debug('renewCertificate')

    const csr = generateSigningRequest(privateKey, this.username, 'FI')

    const request: CertApplicationRequest = {
      '@xmlns': 'http://op.fi/mlp/xmldata/',
      CustomerId: this.username,
      Timestamp: this.formatTime(new Date()),
      Environment: this.environment,
      SoftwareId: app.VERSION_STRING,
      Service: 'MATU',
      Content: csr
    }

    // Convert application request xml.
    const requestXml = this.signApplicationRequest(
      builder
        .create({ CertApplicationRequest: request }, { version: '1.0', encoding: 'UTF-8' })
        .end()
    )

    // Cert service envelopes are not signed.
    const response = await this.makeSoapRequest(
      OsuuspankkiCertService.getEndpoint(this.environment),
      {
        getCertificatein: {
          '@xmlns': 'http://mlp.op.fi/OPCertificateService',
          RequestHeader: {
            SenderId: this.username,
            RequestId: this.requestId(),
            Timestamp: this.formatTime(new Date())
          },
          ApplicationRequest: Buffer.from(requestXml).toString('base64')
        }
      }
    )

    const applicationResponse = await app.parseApplicationResponse(
      response,
      this.verifyRequestCallback
    )

    const {
      CertApplicationResponse: {
        Certificates: {
          Certificate: { Name, Certificate, CertificateFormat }
        }
      }
    } = applicationResponse

    const newCert = pki.certificateToPem(X509ToCertificate(Certificate))

    // Start using the new key
    this.key = new Key(privateKey, newCert)

    return newCert
  }
}
