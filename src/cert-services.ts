import * as builder from 'xmlbuilder'
import * as xpath from 'xpath'
import SoapClient from './soap'
import TrustStore from './trust'
import { X509ToCertificate } from './xml'
import * as app from './application'
import { OPPohjola, OPPohjolaTest } from './cacerts/OP-Pohjola'
import { NordeaServices as NordeaServicesCert } from './cacerts/Nordea'
import { debug, CertApplicationRequest } from './pankkiyhteys'

export class OsuuspankkiCertService extends SoapClient implements app.CertService {
  username: string
  environment: app.Environment

  constructor(username: string, environment: app.Environment = app.Environment.PRODUCTION) {
    super()

    this.username = username
    this.environment = environment
  }

  getEndpoint(environment: app.Environment): string {
    return {
      [app.Environment.PRODUCTION]: 'https://wsk.op.fi/services/OPCertificateService',
      [app.Environment.TEST]: 'https://wsk.asiakastesti.op.fi/services/OPCertificateService'
    }[environment]
  }

  applicationRequestXmlns = 'http://op.fi/mlp/xmldata/'
  certificateRequestXmlns = 'http://mlp.op.fi/OPCertificateService'

  getRootCA(): string[] {
    return {
      [app.Environment.PRODUCTION]: [OPPohjola],
      [app.Environment.TEST]: [OPPohjolaTest]
    }[this.environment]
  }

  async addIntermediaryCertificates(trustStore: TrustStore): Promise<void> {
    debug('getServiceCertificates')

    const request: CertApplicationRequest = {
      '@xmlns': this.applicationRequestXmlns,
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
    const response = await this.makeSoapRequest(this.getEndpoint(this.environment), {
      getServiceCertificatesin: {
        '@xmlns': this.certificateRequestXmlns,
        RequestHeader: {
          SenderId: this.username,
          RequestId: this.requestId(),
          Timestamp: this.formatTime(new Date())
        },
        ApplicationRequest: Buffer.from(requestXml).toString('base64')
      }
    })

    // Use preprocess callback that adds certificates to trust store.
    // Otherwise we might not have intermediary certificates before signature validation.
    await app.parseApplicationResponse(response, async (xml, document) => {
      const certificates = xpath.select(
        "/*/*[local-name()='Certificates']/*[local-name()='Certificate']",
        document
      )

      for (const cert of certificates as Array<any>) {
        if (cert) {
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

export class NordeaCertService extends SoapClient implements app.CertService {
  getEndpoint(): string {
    return `https://filetransfer.nordea.com/services/CertificateService`
  }

  applicationRequestXmlns = 'http://bxd.fi/xmldata/'
  certificateRequestXmlns = this.getEndpoint()

  getRootCA(): string[] {
    return [NordeaServicesCert]
  }

  async addIntermediaryCertificates(): Promise<void> {
    console.warn('Adding intermediary certificates is not implemented for Nordea.')
  }
}
