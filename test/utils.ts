import * as fs from 'fs'
import * as path from 'path'
import { promisify } from 'util'
import { pki } from 'node-forge'
import { Key } from '../src/trust'

/**
 * Read file.
 *
 * Paths are relative to test/ directory.
 */
export const readFile = (filename: string, encoding = 'utf8') =>
  promisify(fs.readFile)(path.join(__dirname, filename), encoding)

interface KeyGenerationErrors {
  /** Generate expired certificate */
  expired?: true
  /** Generate almost expired certificate */
  expiring?: true
  /** Generate unsigned certificate */
  notSigned?: true
}

interface KeyPair {
  privateKey: pki.PrivateKey
  cert: pki.Certificate
}

export function forgeToKey(pair: KeyPair) {
  return new Key(pki.privateKeyToPem(pair.privateKey), pki.certificateToPem(pair.cert))
}

/**
 * Generate rsa keys and certificates for testing purposes.
 */
export async function createCertificate(
  name: string,
  signee?: KeyPair,
  errors: KeyGenerationErrors = {}
): Promise<KeyPair> {
  const privateKey = pki.privateKeyFromPem(await Key.generateKey())
  const publicKey = pki.rsa.setPublicKey((privateKey as any).n, (privateKey as any).e)
  const cert = pki.createCertificate()

  cert.publicKey = publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()

  if (errors.expired) {
    cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 5)
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 4)
  } else if (errors.expiring) {
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + 2)
  } else {
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
  }

  // Generate expired certificate

  const attrsIssuer = [
    {
      name: 'commonName',
      value: 'example.com'
    },
    {
      name: 'organizationName',
      value: name
    }
  ]

  cert.setSubject(attrsIssuer)

  if (!signee) {
    // self-sign certificate
    cert.setIssuer(attrsIssuer)

    if (!errors.notSigned) {
      cert.sign(privateKey)
    }
  } else {
    cert.setIssuer(signee.cert.subject.attributes)

    if (!errors.notSigned) {
      cert.sign(signee.privateKey)
    }
  }

  return {
    privateKey,
    cert
  }
}
