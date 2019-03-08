/**
 * @file Test file module
 *
 * These tests were probabaly not the best use of my time...
 */

import * as file from '../src/file'
import * as path from 'path'
import * as os from 'os'
import * as fs from 'fs'

// Mock file module
jest.mock('fs')

const mockedFs = fs as jest.Mocked<typeof fs>

describe('Test file module', () => {
  const testFile = path.join(os.tmpdir(), 'test')

  it('Test create directory', async () => {
    // Success creating directory
    mockedFs.mkdir.mockImplementation(((path: any, callback: any) => {
      expect(path).toEqual(testFile)
      callback()
    }) as any)

    await file.createDirectory(testFile)

    // Fail creating directory
    mockedFs.mkdir.mockImplementation(((path: any, callback: any) => {
      expect(path).toEqual(testFile)
      callback('Error')
    }) as any)

    await expect(file.createDirectory(testFile)).rejects.toBeTruthy()
  })

  it('Test read directory', async () => {
    const value = 'my-file.txt'

    // Success reading directory
    mockedFs.readdir.mockImplementation(((path: any, callback: any) => {
      expect(path).toEqual(testFile)
      callback(null, [value])
    }) as any)

    expect(await file.readDirectory(testFile)).toEqual([value])

    // Fail reading directory
    mockedFs.readdir.mockImplementation(((path: any, callback: any) => {
      expect(path).toEqual(testFile)
      callback('Error!')
    }) as any)

    await expect(file.readDirectory(testFile)).rejects.toBeTruthy()
  })

  it('Test read file', async () => {
    const content = 'Hello world'

    expect.assertions(4)

    // Success reading file
    mockedFs.readFile.mockImplementation(((path: any, encoding: any, callback: any) => {
      expect(path).toEqual(testFile)
      callback(null, content)
    }) as any)

    expect(await file.readFile(testFile)).toEqual(content)

    // Fail reading file
    mockedFs.readFile.mockImplementation(((path: any, encoding: any, callback: any) => {
      expect(path).toEqual(testFile)
      callback('Error!')
    }) as any)

    await expect(file.readFile(testFile)).rejects.toBeTruthy()
  })

  it('Test write file', async () => {
    const content = 'Hello world'

    expect.assertions(5)

    // Success writing file
    mockedFs.writeFile.mockImplementation(((path: any, data: any, callback: any) => {
      expect(path).toEqual(testFile)
      expect(data).toEqual(content)

      callback(null)
    }) as any)

    await file.writeFile(testFile, content)

    // Fail writing file
    mockedFs.writeFile.mockImplementation(((path: any, data: any, callback: any) => {
      expect(path).toEqual(testFile)
      expect(data).toEqual(content)

      callback('Error!')
    }) as any)

    await expect(file.writeFile(testFile, content)).rejects.toBeTruthy()
  })
})
