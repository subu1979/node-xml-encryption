# @subu1979/xml-encryption

A secure XML Encryption library with enhanced security features and modern Node.js compatibility.

## Overview

This package is a fork of the original `node-xml-encryption` library with the following improvements:

- **Enhanced Security**: Updated dependencies to eliminate security vulnerabilities
- **Modern Node.js Support**: Compatible with Node.js 16+ and includes fixes for deprecated crypto methods
- **Deprecated Algorithm Warnings**: Built-in warnings for insecure encryption algorithms
- **Improved Error Handling**: Better error messages and fallback mechanisms

## Installation

```bash
npm install @subu1979/xml-encryption
```

## Security Features

### Deprecated Algorithm Detection
The library automatically detects and warns about the use of deprecated encryption algorithms:

- `http://www.w3.org/2001/04/xmlenc#rsa-1_5` (RSA PKCS#1 v1.5)
- `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` (Triple DES)

### Secure Alternatives
Use these modern, secure algorithms instead:

- **RSA**: `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`
- **AES**: `http://www.w3.org/2009/xmlenc11#aes128-gcm` or `http://www.w3.org/2009/xmlenc11#aes256-gcm`

## Usage

```javascript
const xmlenc = require('@subu1979/xml-encryption');

// Encrypt XML content
xmlenc.encrypt(xmlContent, {
  rsa_pub: publicKey,
  pem: certificate,
  encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
  keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
}, (err, encrypted) => {
  if (err) throw err;
  console.log('Encrypted:', encrypted);
});

// Decrypt XML content
xmlenc.decrypt(encryptedXml, {
  key: privateKey,
  disallowDecryptionWithInsecureAlgorithm: true
}, (err, decrypted) => {
  if (err) throw err;
  console.log('Decrypted:', decrypted);
});
```

## Configuration Options

### Security Options

- `disallowEncryptionWithInsecureAlgorithm`: Set to `true` to prevent encryption with deprecated algorithms
- `disallowDecryptionWithInsecureAlgorithm`: Set to `true` to prevent decryption with deprecated algorithms
- `warnInsecureAlgorithm`: Set to `true` to show warnings for deprecated algorithms (default: `true`)

### Encryption Algorithms

#### Symmetric Encryption
- `http://www.w3.org/2001/04/xmlenc#aes128-cbc` (AES-128-CBC)
- `http://www.w3.org/2001/04/xmlenc#aes256-cbc` (AES-256-CBC)
- `http://www.w3.org/2009/xmlenc11#aes128-gcm` (AES-128-GCM) ⭐ **Recommended**
- `http://www.w3.org/2009/xmlenc11#aes256-gcm` (AES-256-GCM) ⭐ **Recommended**

#### Key Encryption
- `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` ⭐ **Recommended**
- `http://www.w3.org/2001/04/xmlenc#rsa-1_5` ⚠️ **Deprecated**

## Breaking Changes from Original

- Package name changed to `@subu1979/xml-encryption`
- Minimum Node.js version: 16.0.0
- Deprecated algorithms are now blocked by default when security options are enabled
- Enhanced error handling for deprecated crypto methods

## Testing

```bash
npm test
```

## License

MIT License - see LICENSE file for details.

## Contributing

This is a maintained fork focused on security and modern Node.js compatibility. For original package issues, please refer to the upstream repository.

## Security

If you discover a security vulnerability, please report it responsibly. This package includes:

- Regular dependency updates
- Security vulnerability scanning
- Deprecated algorithm warnings
- Modern crypto method support
