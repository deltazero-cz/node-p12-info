# Parse P12 (PKCS #12) certificates

Verify Password & Parse Information from PKCS #12 certificates (.p12 or .pfx)

Based on [node-forge](https://www.npmjs.com/package/node-forge).

### Quick Usage

```js
import p12info from 'p12-info'

const parsed = p12info(certBuffer, certPassword)
console.log(parsed)
```

```json
{
  "friendlyName": "Dummy Cert",
  "subject": {
    "countryName": "CZ",
    "stateOrProvinceName": "Prague",
    "localityName": "Prague",
    "organizationName": "Delta Zero",
    "organizationalUnitName": "Test",
    "commonName": "Dummy Cert",
    "emailAddress": "spam@deltazero.cz"
  },
  "issuer": {
    "countryName": "CZ",
    "stateOrProvinceName": "Prague",
    "localityName": "Prague",
    "organizationName": "Delta Zero",
    "organizationalUnitName": "Test",
    "commonName": "Dummy Cert",
    "emailAddress": "spam@deltazero.cz"
  },
  "serialNumber": "00c0e2afc8f5fedcd4",
  "version": 0,
  "validity": {
    "notBefore": "2022-06-15T19:29:08.000Z",
    "notAfter": "2032-06-12T19:29:08.000Z"
  },
  "isValid": true
}
```

