const { Osuuspankki, Key } = require('./index')
const { readFile, writeFile } = require('fs').promises

function isExpiringInMonths(key, months) {
  const dateToCheck = new Date()
  dateToCheck.setMonth(dateToCheck.getMonth() + months)

  return key.expires() < dateToCheck
}

Promise.all([readFile('./newkey.pem', 'utf8'), readFile('./newcert.pem', 'utf8')]).then(
  async ([privateKey, cert]) => {
    const key = new Key(privateKey, cert)
    const client = new Osuuspankki('1000061998', key, 'FI')

    if (isExpiringInMonths(key, 2)) {
      console.log('Certificate is about to expire', key.expires())

      const keys = await Key.generateKey()

      // Must save key to persistent storage before attempting to use it.
      await writeFile('./newkey.pem', keys.privateKey)

      const certificate = await client.getCertificate(keys.privateKey)

      // Must save certificate to persistent storage before continuing.
      await writeFile('./newcert.pem', certificate)
    }

    // client.getFileList({ Status: 'DLD' }).then(console.log)
    client.getFile('301930168').then(res => console.log(res.toString()))
  }
)
