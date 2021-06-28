/**
 * @file Helper functions for generating and processing application requests
 */

import * as builder from 'xmlbuilder'
import * as parser from 'fast-xml-parser'
import * as xpath from 'xpath'
import * as zlib from 'zlib'
import { promisify } from 'util'
import { DOMParser } from 'xmldom'
import { namespaces, isElementSigned, X509ToCertificate } from './xml'
import createDebug from 'debug'
import TrustStore, { Key, sign, verifySignature } from './trust'
import SoapClient from './soap'

const debug = createDebug('pankkiyhteys')
const gunzip = promisify(zlib.gunzip)

export const VERSION_STRING = 'pankkiyhteys v0.10'

type XMLDocument = any
type XMLElement = Node

export interface ApplicationRequest {
  '@xmlns': 'http://bxd.fi/xmldata/'
  /** Code used by the bank to identify the customer who originated this request. */
  CustomerId: string
  /** This element specifies the requested operation. */
  Command?: string
  /** Time and date when the Application Request Header was created. */
  Timestamp: string
  /** When requesting data from the bank, e.g. with the DownloadFileList operation, this element can be used to specify filtering criteria */
  StartDate?: string
  /** When requesting data from the bank, e.g. with the DownloadFileList operation, this element can be used to specify filtering criteria. */
  EndDate?: string
  /** When requesting data from the bank, e.g. with the DownloadFileList operation, this element can be used to specify filtering criteria. */
  Status?: 'NEW' | 'DLD' | 'ALL'
  /** Additional identification information of the Customer */
  ServiceId?: string
  /** Specifies which environment the request is meant for. */
  Environment: 'TEST' | 'PRODUCTION'
  /** Unique identification of the file that is the target of the operation. */
  FileReferences?: { FileReference: string }
  /** A name given to the file by the customer. */
  UserFileName?: string
  /** The logical folder name where the file(s) of the customer are stored in the bank. A user can have access to several folders. */
  TargetId?: string
  /** An identifier given the customer to identify this particular request. */
  ExecutionSerial?: string
  /** Encrytion indicator for the content or encryption request for the responses. */
  Encryption?: 'true' | 'false'
  /** Name of the encryption algorithm. */
  EncryptionMethod?: string
  /** Compression indicator for the content and compression request for the responses. */
  Compression?: 'true' | 'false'
  /** Name of the compression algorithm. */
  CompressionMethod?: 'RFC1952'
  /** Total sum of amounts in the file. */
  AmountTotal?: string
  /** Total sum of transactions in the file. */
  TransactionCount?: string
  /** This element contains the name and version of the client side software. */
  SoftwareId: string
  /** Customer, bank, country or region specific elements not already contained in the schema. */
  CustomerExtension?: any
  /** Specifies the type of file in the request. Can also be used as a filter in the operation DownloadFileList. */
  FileType?: string
  /** The actual file in the UploadFile operation. */
  Content?: string
}

export interface ResponseHeader {
  SenderId: string
  RequestId: string
  Timestamp: string
  ResponseCode: string
  ResponseText: string
}

export type Language = 'EN' | 'FI' | 'SV'

export const enum Environment {
  PRODUCTION = 'PRODUCTION',
  TEST = 'TEST'
}

export interface GetFileListOptions {
  StartDate?: string
  EndDate?: string
  Status?: 'NEW' | 'DLD' | 'ALL'
  FileType?: string
}

export type ParsePreprocess = (xml: string, document: XMLDocument) => Promise<void> | void

export interface CertService {
  /**
   * Get root CA certificates
   */
  getRootCA(): Array<string>

  /**
   * Add intermediary certficates to trustStore.
   */
  addIntermediaryCertificates(trustStore: TrustStore): Promise<void>
}

export class Client extends SoapClient {
  username: string
  key: Key
  language: Language
  /** Bank identification code */
  bic: string
  endpoint: string
  environment: Environment
  trustStore: TrustStore

  constructor(
    username: string,
    key: Key,
    language: Language,
    bic: string,
    endpoint: string,
    certService: CertService,
    environment = Environment.PRODUCTION
  ) {
    super()

    this.username = username
    this.key = key
    this.language = language
    this.bic = bic
    this.endpoint = endpoint
    this.environment = environment

    // Initialize truststore with knowledge of how to fetch intermediary certificates.
    this.trustStore = new TrustStore(certService.getRootCA(), async () => {
      await certService.addIntermediaryCertificates(this.trustStore)
    })
  }

  /**
   * Get list of files
   */
  async getFileList(options: GetFileListOptions = {}): Promise<any> {
    const response = await this.makeRequest('downloadFileListin', {
      '@xmlns': 'http://bxd.fi/xmldata/',
      CustomerId: this.username,
      Timestamp: this.formatTime(new Date()),
      StartDate: options.StartDate,
      EndDate: options.EndDate,
      Status: options.Status,
      Environment: this.environment,
      SoftwareId: VERSION_STRING,
      FileType: options.FileType
    })

    if (Array.isArray(response.ApplicationResponse.FileDescriptors.FileDescriptor)) {
      return response.ApplicationResponse.FileDescriptors.FileDescriptor
    }

    return [response.ApplicationResponse.FileDescriptors.FileDescriptor]
  }

  /**
   * Download file
   *
   * The client must have obtained the fileReference value beforehand, e.g.
   * using the getFileList or uploadFile operations.
   *
   * @param fileReference Unique identification of the file.
   */
  async getFile(fileReference: string): Promise<Buffer> {
    const response = await this.makeRequest('downloadFilein', {
      '@xmlns': 'http://bxd.fi/xmldata/',
      CustomerId: this.username,
      Timestamp: this.formatTime(new Date()),
      Environment: this.environment,
      FileReferences: { FileReference: fileReference },
      Compression: 'true',
      CompressionMethod: 'RFC1952',
      SoftwareId: VERSION_STRING
    })

    const { Compressed, CompressionMethod, Content } = response.ApplicationResponse

    // Return decompressed buffer.
    if (Compressed) {
      if (CompressionMethod !== 'RFC1952') {
        throw new Error(`Unsupported compression method ${CompressionMethod}`)
      }

      return gunzip(Buffer.from(Content, 'base64')) as Promise<Buffer>
    }

    // Retrun content if data is not compressed.
    return Buffer.from(Content, 'base64')
  }

  /**
   * Make request to corporate file service.
   *
   * @param service Request type
   * @param applicationRequest Request payload
   * @param preprocess Callback to act on response before the signature is verified
   * @param sign True and the request payload will be signed
   */
  async makeRequest(
    service: string,
    applicationRequest: ApplicationRequest,
    timestamp = new Date()
  ) {
    debug('Request %s', service)

    // Convert application request xml.
    const xml = this.signApplicationRequest(
      builder
        .create({ ApplicationRequest: applicationRequest }, { version: '1.0', encoding: 'UTF-8' })
        .end()
    )

    const response = await this.makeSoapRequest(
      this.endpoint,
      {
        [`cfs:${service}`]: {
          '@xmlns': 'http://model.bxd.fi',
          '@xmlns:cfs': 'http://bxd.fi/CorporateFileService',
          RequestHeader: {
            SenderId: this.username,
            RequestId: this.requestId(),
            Timestamp: this.formatTime(timestamp),
            Language: this.language,
            UserAgent: VERSION_STRING,
            ReceiverId: this.bic
          },
          ApplicationRequest: Buffer.from(xml).toString('base64')
        }
      },
      this.key,
      this.trustStore
    )

    const header = parseResponseHeader(response)

    debug('Response %s = %s', service, header.ResponseText)
    if (parseInt(header.ResponseCode, 10) !== 0) {
      debug('%o', header)

      throw new Error(`Error: ${header.ResponseCode}: ${header.ResponseText}`)
    }

    // Use preprocess callback that adds certificates to trust store.
    // Otherwise we might not have intermediary certificates before signature validation.
    const applicationResponse = await parseApplicationResponse(response, this.verifyRequestCallback)

    return {
      Header: header,
      ...(applicationResponse as {
        ApplicationResponse: any
      })
    }
  }

  /**
   * Sign application request
   *
   * @param xml
   */
  protected signApplicationRequest(xml: string) {
    return sign(xml, this.key, [], {
      canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    })
  }

  /**
   * Verify request signature in application request parsing callback
   */
  public verifyRequestCallback: ParsePreprocess = async (xml, document) => {
    await verifyApplicationRequestSignature(xml, document, this.trustStore)
  }
}

/**
 * Parse response header.
 *
 * @param response XML response element
 */
export function parseResponseHeader(response: XMLElement): ResponseHeader {
  const header = xpath.select("./*[local-name()='ResponseHeader']/*/text()", response)
  const data: any = {}

  if (header) {
    for (let node of header as Array<any>) {
      data[node.parentNode.nodeName] = node.data
    }
  }

  return data
}

/**
 * Parse application response
 *
 * @param response Soap envelope body content.
 * @param preprocess Preprocess ApplicationResponse callback
 */
export async function parseApplicationResponse(response: XMLElement, preprocess?: ParsePreprocess) {
  const { data } = xpath.select(
    "./*[local-name()='ApplicationResponse']/text()",
    response,
    true
  ) as any

  const xml = Buffer.from(data, 'base64').toString()
  const document = new DOMParser().parseFromString(xml)

  // Preprocess callback allows client to access request prefore signature verification.
  if (preprocess) {
    await preprocess(xml, document)
  }

  // Return parsed response
  return parser.parse(xml, { ignoreNameSpace: true })
}

/**
 * Verify xml signature
 *
 * In order to protect from some attacks caller must check the content they
 * want to use is the one that has been signed.
 *
 * Having a signature makes no sense otherwise.
 *
 * @param xml xml document
 * @param signature signature xml element
 *
 * @throws if signature verification fails
 */
export async function verifyApplicationRequestSignature(
  xml: string,
  document: any,
  trustStore: TrustStore,
  noLoading = false
) {
  const select = xpath.useNamespaces({ dsig: namespaces.dsig })
  const signature = select('/*/dsig:Signature', document, true) as Node
  const certificateText = select(
    './dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate/text()',
    signature,
    true
  )

  if (!certificateText) {
    throw new Error('dsig:Signature is malformed')
  }

  const certificate = X509ToCertificate(certificateText.toString())

  if (!isElementSigned(document, signature)) {
    throw new Error('ApplicationRequest is not signed')
  }

  // Certificate must be trusted.
  if (!(await trustStore.isCertificateTrusted(certificate, noLoading))) {
    throw new Error('Signature key is not trusted')
  }

  if (!verifySignature(xml, signature, certificate)) {
    throw new Error('Signature verification failed')
  }

  return true
}
