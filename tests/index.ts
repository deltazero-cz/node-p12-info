import p12info, { readRaw } from '../index.js'
import { expect } from 'chai'
import { readFileSync } from 'fs'

const file = readFileSync('./tests/foo.p12'),
      pass = 'test1234'

describe('Parse Certificate', () => {
  const parsed = p12info(file, pass)
  // console.log(parsed)

  it ('Friendly Name', () => {
    expect(parsed.friendlyName).to.be.equal('Dummy Cert')
  })

  it ('Subject', () => {
    expect(parsed.subject.commonName).to.be.equal('Dummy Cert')
    expect(parsed.subject.organizationName).to.be.equal('Delta Zero')
  })

  it ('Issuer', () => {
    expect(parsed.subject.commonName).to.be.equal('Dummy Cert')
    expect(parsed.subject.countryName).to.be.equal('CZ')
  })

  it ('Serial Number', () => {
    expect(parsed.serialNumber).to.be.equal('00c0e2afc8f5fedcd4')
  })

  it ('Validity', () => {
    expect(parsed.isValid).be.a('boolean')
    expect(parsed.validity.notBefore).be.a('date')
    expect(parsed.validity.notAfter).be.a('date')
  })

  it ('Valid before date', () => {
    expect(parsed.isValid).to.equal(new Date() < new Date('2032-06-12T19:29:08.000Z'))
  })

})

describe('Read Raw', () => {
  const data = readRaw(file, pass)
  // console.log(data)

  it ('Friendly Name', () => {
    expect(data.attributes.friendlyName[0]).to.be.equal('Dummy Cert')
  })

  it ('Public Key', () => {
    expect(data.cert.publicKey.n.toString().length).to.be.equal(1233)
  })

  it ('Algorithm', () => {
    expect(data.cert.md.algorithm).to.be.equal('sha256')
  })
})

describe('Fail to Read', () => {
  it ('Wrong Certificate File', () => {
    // @ts-ignore
    expect(() => readRaw('hovno', pass)).to.throw('Too few bytes')
  })

  it ('Incomplete Certificate File', () => {
    expect(() => readRaw(file.slice(0, 4200), pass)).to.throw('Too few bytes')
  })

  it ('Wrong Password', () => {
    expect(() => readRaw(file, pass+'x')).to.throw('Invalid password')
  })
})
