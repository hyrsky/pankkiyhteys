import * as fs from 'fs'

/**
 * Create directory or no-op if it already exists.
 *
 * @param directory Directory path
 */
export function createDirectory(directory: string) {
  // Attempt to create temporary directory
  return new Promise<string>((resolve, reject) => {
    fs.mkdir(directory, err => {
      if (err && err.code !== 'EEXIST') {
        return reject(err)
      }

      resolve()
    })
  })
}

/**
 * Return list of filenames in a directory.
 *
 * @param directory Directory path
 */
export function readDirectory(directory: string) {
  return new Promise<string[]>((resolve, reject) =>
    fs.readdir(directory, (err, files) => (err ? reject(err) : resolve(files)))
  )
}

/**
 * Read content of a file.
 *
 * @param filename File path
 */
export function readFile(filename: string) {
  return new Promise<string>((resolve, reject) =>
    fs.readFile(filename, 'utf8', (err, data) => {
      if (err) {
        return reject(err)
      }

      resolve(data)
    })
  )
}

/**
 * Write content to file
 *
 * @param filename File path
 * @param data Content
 */
export function writeFile(filename: string, data: string | Buffer) {
  return new Promise<string>((resolve, reject) =>
    fs.writeFile(filename, data, err => {
      if (err) {
        return reject(err)
      }

      resolve()
    })
  )
}
