import { mkdir, readdir, readFile, writeFile } from 'fs'
import { promisify } from 'util'

export default {
  mkdir: promisify(mkdir),
  readdir: promisify(readdir),
  readFile: promisify(readFile),
  writeFile: promisify(writeFile),
}
