type DOMImplementation = any
type XPathNSResolver = any
type XPathResult = any
type Attr = any
type Document = any
type Node = any

declare module 'xml-crypto' {
  interface ComputeSignatureOptions {
    prefix?: string
    attrs?: any
    location?: {
      reference: string
      action?: 'append' | 'prepend' | 'before' | 'after'
    }
    existingPrefixes?: {
      [key: string]: string
    }
  }

  interface SignKeyInfoProvider {
    getKeyInfo(key: string, prefix: string): string
  }
  interface VerifyKeyInfoProvider {
    getKey(keyInfo: any): string
  }

  export type KeyInfoProvider = SignKeyInfoProvider | VerifyKeyInfoProvider

  export class SignedXml {
    constructor(idMode?: string)
    signingKey: string
    keyInfoProvider: SignKeyInfoProvider | VerifyKeyInfoProvider
    canonicalizationAlgorithm: string
    addReference(
      xpath: string,
      transforms?: [string],
      digestAlgorithm?: string,
      uri?: string,
      digestValue?: string,
      inclusiveNamespacesPrefixList?: any,
      isEmptyUri?: boolean
    ): void
    computeSignature(xml: string, options?: ComputeSignatureOptions): void
    getSignedXml(): string
    loadSignature(signature: any): void
    checkSignature(xml: string): boolean
  }

  export function xpath(doc: string, selector: string): any
}
