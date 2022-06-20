import * as forge from 'node-forge'

type AnyObject = {
  [key: string]: any
}

type Attribute = {
  name: string,
  value: string,
  [key: string]: any
}

type CertConf = {
  commonName?: string,
  organizationName?: string,
  organizationUnit?: string,
  locality?: string,
  stateOrProvinceName?: string,
  countryName?: string,
  emailAddress?: string,
}

export type InfoType = {
  friendlyName?: string,
  subject: CertConf,
  issuer: CertConf,
  serialNumber: string,
  version: number,
  validity: {
    notBefore: Date,
    notAfter: Date,
  },
  isValid: Boolean,
  altNames?: string[]
}

export const readRaw = (cert: Buffer, pass: string) : AnyObject => {
  const p12Asn1 = forge.asn1.fromDer(cert.toString('binary'))
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, pass)
  const data = p12.getBags({ bagType: forge.pki.oids.certBag })

  if (!data || !data?.[forge.pki.oids.certBag]?.[0])
    throw new Error('Unable to parse certificate. Incorrect Password?')

  // @ts-ignore
  return data[forge.pki.oids.certBag][0]
}

export default function p12info(cert: Buffer, pass: string) : InfoType {
  const data = readRaw(cert, pass)
  return {
    friendlyName: data.attributes.friendlyName[0],

    subject: data.cert.subject?.attributes.reduce((a: AnyObject, r: Attribute) => {
      r.name && (a[r.name] = Buffer.from(r.value, 'latin1').toString())
      return a
    }, {}),

    issuer: data.cert.issuer?.attributes.reduce((a: AnyObject, r: Attribute) => {
      r.name && (a[r.name] = Buffer.from(r.value, 'latin1').toString())
      return a
    }, {}),

    serialNumber: data.cert.serialNumber,

    version: data.cert.version,

    validity: data.cert.validity,

    isValid: data.cert.validity.notBefore <= new Date() && data.cert.validity.notAfter >= new Date(),

    altNames: data.cert.extensions
        .find((r: Attribute) => r.name = 'subjectAltName')
        ?.altNames?.map((r: Attribute) => r.value)
  }
}
