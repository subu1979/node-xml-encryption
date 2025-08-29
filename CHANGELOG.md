# Changelog

All notable changes to this project will be documented in this file.

## [3.1.0] - 2025-08-29

### Changed
- **BREAKING**: Package name changed from `xml-encryption` to `@subu1979/xml-encryption`
- **BREAKING**: Minimum Node.js version increased to 16.0.0
- **BREAKING**: RSA_PKCS1_PADDING is now blocked by default in Node.js 22+ due to deprecation

### Security
- Updated all dependencies to eliminate security vulnerabilities:
  - `mocha`: 7.1.2 → 11.7.1 (fixes critical security issues)
  - `sinon`: 9.0.2 → 17.0.1 (fixes security vulnerabilities)
  - `@xmldom/xmldom`: 0.8.5 → 0.8.11 (latest secure version)
  - `xpath`: 0.0.32 → 0.0.34 (latest version)
- Added Node.js version compatibility check for deprecated crypto methods
- Enhanced security warnings for deprecated encryption algorithms

### Enhanced Features
- **Modern Node.js Support**: Full compatibility with Node.js 16+ and 22+
- **Deprecated Algorithm Detection**: Automatic detection and blocking of insecure algorithms
- **Improved Error Handling**: Better error messages for deprecated crypto methods
- **Security Options**: Enhanced security configuration options

### Deprecated Algorithms
The following algorithms are now deprecated and blocked by default in Node.js 22+:
- `http://www.w3.org/2001/04/xmlenc#rsa-1_5` (RSA PKCS#1 v1.5)
- `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` (Triple DES)

### Recommended Algorithms
Use these modern, secure algorithms instead:
- **RSA Key Encryption**: `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`
- **Symmetric Encryption**: `http://www.w3.org/2009/xmlenc11#aes128-gcm` or `http://www.w3.org/2009/xmlenc11#aes256-gcm`

### Configuration
New security options available:
- `disallowEncryptionWithInsecureAlgorithm`: Set to `true` to prevent encryption with deprecated algorithms
- `disallowDecryptionWithInsecureAlgorithm`: Set to `true` to prevent decryption with deprecated algorithms
- `warnInsecureAlgorithm`: Set to `true` to show warnings for deprecated algorithms (default: `true`)

### Migration Guide
If you're upgrading from the original `xml-encryption` package:

1. Update your package.json:
   ```json
   {
     "dependencies": {
       "@subu1979/xml-encryption": "^3.1.0"
     }
   }
   ```

2. Update your require statements:
   ```javascript
   // Old
   const xmlenc = require('xml-encryption');
   
   // New
   const xmlenc = require('@subu1979/xml-encryption');
   ```

3. Update deprecated algorithm usage:
   ```javascript
   // Old (deprecated)
   keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
   
   // New (recommended)
   keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
   ```

4. Enable security options:
   ```javascript
   const options = {
     // ... other options
     disallowEncryptionWithInsecureAlgorithm: true,
     disallowDecryptionWithInsecureAlgorithm: true
   };
   ```

### Testing
- All existing tests updated to use modern algorithms
- New tests added for security features
- Test suite now passes with 0 vulnerabilities
- Enhanced test coverage for deprecated algorithm handling

### Documentation
- Comprehensive README with security best practices
- Migration guide for existing users
- Security configuration examples
- Algorithm compatibility matrix
