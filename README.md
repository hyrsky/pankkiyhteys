[![Build Status](https://travis-ci.org/hyrsky/pankkiyhteys.svg?branch=master)](https://travis-ci.org/hyrsky/pankkiyhteys)

# Pankkiyhteys

This library is an implementation of Web Services API, a standardised solution used for automated communications between banks and corporate customers.

Currently only [Osuuspankki](https://www.op.fi/) is supported.

For in depth technical documentation about Web Services [click here](https://www.finanssiala.fi/wp-content/uploads/2021/03/WebServices_Messages_v110_20200504.pdf).

## Install

Install with [npm](https://www.npmjs.com/):

```
  npm install pankkiyhteys
```

## Usage

Autogenerated docs at: https://hyrsky.github.io/pankkiyhteys

### Request certificate with transfer key

```js
import { promises as fs } from "fs";

const client = new Osuuspankki('1234567890', undefined, 'FI')
const privateKey = await Key.generateKey();

await fs.writeFile(`private-key-${new Date().toISOString()}.key`, privateKey);

const cert = await client.getInitialCertificate(privateKey, "0123456789ABCDEF");

await fs.writeFile(`certificate-${new Date().toISOString()}.pem`, cert);
```

### Renewing certificate

```js
function isAboutToExpire(key) {
  const dateToCheck = new Date()
  dateToCheck.setMonth(dateToCheck.getMonth() + 2)
  return key.expires() < dateToCheck
}

const key = new Key(oldPrivateKey, oldCert)
const client = new Osuuspankki('1234567890', key, 'FI')

if (key.isAboutToExpire()) {
  /**
   * You have to:
   *   * generate new key.
   *   * save key to persistent storage before renewal.
   */
  const keys = await Key.generateKey()
  await writeFile('./newkey.pem', keys.privateKey)
  const certificate = await client.getCertificate(keys.privateKey)
  await writeFile('./newcert.pem', certificate)
}
```
