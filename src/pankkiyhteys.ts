/**
 * @file Main entrypoint
 */

import createDebug from 'debug'

import { generateSigningRequest, Key } from './trust'
import * as app from './application'
import * as builder from 'xmlbuilder'

import { OsuuspankkiCertService, NordeaCertService } from './cert-services'
import { X509ToCertificate } from './xml'
import { pki } from 'node-forge'

export const debug = createDebug('pankkiyhteys')

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

export { Key } from './trust'

export interface CertApplicationRequest {
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

export class Osuuspankki extends app.Client {
  constructor(
    username: string,
    key: Key | undefined,
    language: app.Language,
    environment = app.Environment.PRODUCTION
  ) {
    const certService = new OsuuspankkiCertService(username, environment)
    const endpoint = Osuuspankki.getEndpoint(environment)
    const bic = 'OKOYFIHH'
    const compressionMethod = 'RFC1952'

    super(username, key, language, bic, endpoint, certService, environment, compressionMethod)
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
   * @param privateKey RSA private key (pem)
   */
  async getCertificate(privateKey: string) {
    debug('renewCertificate')

    const csr = generateSigningRequest(privateKey, this.username, 'FI')

    const request: CertApplicationRequest = {
      '@xmlns': this.certService.applicationRequestXmlns,
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
    const response = await this.makeSoapRequest(this.certService.getEndpoint(this.environment), {
      getCertificatein: {
        '@xmlns': this.certService.certificateRequestXmlns,
        RequestHeader: {
          SenderId: this.username,
          RequestId: this.requestId(),
          Timestamp: this.formatTime(new Date())
        },
        ApplicationRequest: Buffer.from(requestXml).toString('base64')
      }
    })

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

  /**
   * Get initial certificate from cert service using transfer key.
   *
   * Private must have following conditions:
   *   * Modulus lenth = 2048
   *   * If key already has signed certificate the current certificate will be returned instead.
   *
   * Client must save the private key to persistent storage before calling this method.
   *
   * @param privateKey RSA private key (pem)
   * @param transferKey Bank issued transfer key
   */
  async getInitialCertificate(privateKey: string, transferKey: string) {
    debug('getInitialCertificate')

    const csr = generateSigningRequest(privateKey, this.username, 'FI')

    const request: CertApplicationRequest = {
      '@xmlns': 'http://op.fi/mlp/xmldata/',
      CustomerId: this.username,
      Timestamp: this.formatTime(new Date()),
      Environment: this.environment,
      SoftwareId: app.VERSION_STRING,
      Service: 'MATU',
      Content: csr,
      TransferKey: transferKey
    }

    // Convert application request xml.
    // Application request is not signed when using transfer key.
    const requestXml = builder
      .create({ CertApplicationRequest: request }, { version: '1.0', encoding: 'UTF-8' })
      .end()

    // Cert service envelopes are not signed.
    const response = await this.makeSoapRequest(this.certService.getEndpoint(this.environment), {
      getCertificatein: {
        '@xmlns': 'http://mlp.op.fi/OPCertificateService',
        RequestHeader: {
          SenderId: this.username,
          RequestId: this.requestId(),
          Timestamp: this.formatTime(new Date())
        },
        ApplicationRequest: Buffer.from(requestXml).toString('base64')
      }
    })

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

export class Nordea extends app.Client {
  constructor(
    username: string,
    key: Key | undefined,
    language: app.Language,
    environment = app.Environment.TEST
  ) {
    const certService = new NordeaCertService()
    const endpoint = Nordea.getEndpoint()
    const bic = 'NDEAFIHH'
    const compressionMethod = 'GZIP'

    super(username, key, language, bic, endpoint, certService, environment, compressionMethod)

    // Fetching itermediary certs is not implemented for the Nordea client,
    // add root certs to intermediaries so that TrustStore.verifyCertificate
    // will use those instead to validate response signatures.
    for (const ca of certService.getRootCA()) {
      this.trustStore.addIntermediary(pki.certificateFromPem(ca))
    }
  }

  private static getEndpoint() {
    return `https://filetransfer.nordea.com/services/CorporateFileService`
  }
}
