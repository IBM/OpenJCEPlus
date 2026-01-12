# Provider Configuration File Format Documentation

This document describes the format and syntax for provider configuration files used in OpenJCEPlus, based on the `ProviderServiceReader.java` implementation and example configuration files [ProviderDefAttrs.config](./src/test/ProviderDefAttrs.config) and [ProviderFIPSDefAttrs.config](./src/test/ProviderFIPSDefAttrs.config).

## Overview

Provider configuration files define cryptographic services, their implementations, aliases, and attributes for Java Cryptography Extension (JCE) providers. These files use a Java Properties format and are parsed by the `ProviderServiceReader` class.

## File Format

Configuration files follow the standard Java Properties format:
- Key-value pairs separated by `=`
- Comments start with `#`
- Multi-line values not supported
- Whitespace around commas in lists is automatically trimmed

---

## Statement Types

The parser recognizes statements based on the number of dot-separated parts in the key:

### 1. Provider Metadata (1 part)

Define basic provider information.

#### Format:
```properties
name = <provider-name>
description = <provider-description>
default = <true|false|1|0>
```

#### Fields:
- **name**: Unique identifier for the provider (required)
- **description**: Human-readable description of the provider (required)
- **default**: Whether to load default provider attributes (optional, values: `true`, `false`, `1`, `0`)

#### Examples:
```properties
name = test
description = OpenJCEPlus-test Provider

name = test-fips
description = OpenJCEPlusFIPS-test Provider

# Load default attributes
default = true
```

#### Parser Behavior:
- Keys with exactly 1 part are checked for `name`, `description`, or `default`
- Invalid single-part keys throw an `IOException`
- When `default = true` or `default = 1`, the parser loads default services from `DefaultProviderAttrs.defaultProvAttrs`

---

### 2. Service Definitions (3 parts)

Register cryptographic service implementations.

#### Format:
```properties
Service.<ServiceType>.<AlgorithmName> = <ImplementationClassName>
```

#### Key Structure:
- **Part 0**: Must be `Service` (case-insensitive)
Service.AlgorithmParameterGenerator.CCM = com.ibm.crypto.plus.provider.CCMParameterGenerator
Service.AlgorithmParameterGenerator.CCM = com.ibm.crypto.plus.provider.CCMParameterGenerator
- **Part 1**: Service type - Cipher, Signature, MessageDigest, SecureRandom, SecretKeyFactory, 
                             KEM, KDF, MAC, KeyPairGenerator, KeyGenerator, KeyFactory, KeyAgreement, 
                             AlgorithmParameterGenerator, AlgorithmParameters, etc. 
                             (see Java Cryptography Architecture API Specification and Reference)
- **Part 2**: Algorithm name or transformation

#### Examples:

**Simple Services:**
```properties
Service.AlgorithmParameters.AES = com.ibm.crypto.plus.provider.AESParameters
Service.MessageDigest.MD5 = com.ibm.crypto.plus.provider.MessageDigest$MD5
Service.Cipher.RSA = com.ibm.crypto.plus.provider.RSA
```

**Services with Transformations:**
```properties
Service.Cipher.AES/GCM/NoPadding = com.ibm.crypto.plus.provider.AESGCMCipher
Service.Cipher.AES/CCM/NoPadding = com.ibm.crypto.plus.provider.AESCCMCipher
Service.Cipher.AES/KW/NoPadding = com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW
```

**Services with Inner Classes:**
```properties
Service.KeyFactory.RSA = com.ibm.crypto.plus.provider.RSAKeyFactory$Legacy
Service.KeyFactory.RSAPSS = com.ibm.crypto.plus.provider.RSAKeyFactory$PSS
Service.SecretKeyFactory.PBKDF2WithHmacSHA256 = com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA256
```

#### Parser Behavior:
- Keys with exactly 3 parts where part[0] is `Service` are recognized as service definitions
- The parser creates a `ServiceDefinition` object with:
  - Type: `parts[1]`
  - Algorithm: `parts[2]`
  - ClassName: property value
  - Aliases: processed from alias statements
  - Attributes: processed from attribute statements

#### Common Service Types:
- **AlgorithmParameters**: Parameter specifications
- **AlgorithmParameterGenerator**: Parameter generators
- **Cipher**: Encryption/decryption engines
- **KeyAgreement**: Key agreement protocols
- **KeyFactory**: Key conversion and specification
- **KeyGenerator**: Symmetric key generators
- **KeyPairGenerator**: Asymmetric key pair generators
- **MAC**: Message Authentication Code engines
- **MessageDigest**: Hash/digest algorithms
- **SecretKeyFactory**: Secret key factories
- **SecureRandom**: Random number generators
- **Signature**: Digital signature engines
- **KDF**: Key Derivation Functions
- **KEM**: Key Encapsulation Mechanisms (PQC)

---

### 3. Alias Definitions (4 parts)

Define alternative names for algorithms.

#### Format:
```properties
<ServiceType>.<AlgorithmName>.alias.<operation> = <Alias1>, <Alias2>, <Alias3>, ...
```

#### Key Structure:
- **Part 0**: Service type (matches Service definition)
- **Part 1**: Algorithm name (matches Service definition)
- **Part 2**: Must be `alias` (case-insensitive)
- **Part 3**: Operation type: `add`, `delete`, or `replace`

#### Operations:

**add**: Adds aliases to the list (cumulative with defaults if applicable)
```properties
AlgorithmParameters.GCM.alias.add = AESGCM
Cipher.AES/KW/NoPadding.alias.add = AESWrap
KeyGenerator.DESede.alias.add = TripleDES, 3DES
```

**delete**: Removes specified aliases from the current list
```properties
# Remove specific aliases
Cipher.AES.alias.delete = OldAlias, DeprecatedName
```

**replace**: Clears all existing aliases and sets new ones
```properties
# Replace all aliases with new set
MessageDigest.SHA-256.alias.replace = SHA256, SHA2
```

#### Examples with OIDs:
```properties
AlgorithmParameters.DiffieHellman.alias.add = DH, OID.1.2.840.113549.1.3.1, 1.2.840.113549.1.3.1
KeyFactory.RSA.alias.add = OID.1.2.5.8.1.1, 1.2.5.8.1.1, OID.1.2.840.113549.1.1.1, 1.2.840.113549.1.1.1
MessageDigest.SHA-1.alias.add = SHA, SHA1, OID.1.3.14.3.2.26, 1.3.14.3.2.26
```

#### Parser Behavior:
- Keys with exactly 4 parts where part[2] is `alias` are recognized as alias definitions
- The value is split by commas with whitespace trimmed: `value.split("\\s*,\\s*")`
- Processing order:
  1. Default aliases are added first (if `default = true`)
  2. Config file `.add` operations are applied
  3. Config file `.delete` operations are applied
  4. Config file `.replace` operations are applied (clears list first)
- Only one operation (add/delete/replace) per service type and algorithm is expected

---

### 4. Attribute Definitions (5 parts)

Define service attributes (properties).

#### Format:
```properties
<ServiceType>.<AlgorithmName>.attr.<operation>.<AttributeName> = <AttributeValue>
```

#### Key Structure:
- **Part 0**: Service type (matches Service definition)
- **Part 1**: Algorithm name (matches Service definition)
- **Part 2**: Must be `attr` (case-insensitive)
- **Part 3**: Operation type: `add` or `delete`
- **Part 4**: Attribute name

#### Operations:

**add**: Adds or updates an attribute
```properties
SecureRandom.SHA256DRBG.attr.add.ThreadSafe = true
SecureRandom.SHA512DRBG.attr.add.ThreadSafe = true
```

**delete**: Removes an attribute
```properties
# Remove an attribute
Cipher.AES.attr.delete.SomeAttribute = ignored
```

#### Parser Behavior:
- Keys with exactly 5 parts where part[2] is `attr` are recognized as attribute definitions
- Processing order:
  1. Default attributes are added first (if `default = true`)
  2. Config file `.add` operations are applied
  3. Config file `.delete` operations are applied
- The attribute name is `parts[4]` and the value is the property value
- For delete operations, the value is ignored (attribute is removed by name)

#### Common Attributes:
- **ThreadSafe**: Indicates if the implementation is thread-safe (`true`/`false`)
- Custom attributes can be defined as needed

---

### 5. Comments

Provide documentation and section separators.

#### Format:
```properties
# Single line comment
# =======================================================================
#  Section Header
# =======================================================================
#
```

#### Examples:
```properties
# This is a comment
# ChaCha20 and ChaCha20-Poly1305 not supported in FIPS mode

# =======================================================================
#  Cipher engines
# =======================================================================
#
```

---

## Processing Order

When `ProviderServiceReader.readServices()` is called:

1. **Load Properties**: File is loaded using `Properties.load()`
2. **Parse Keys**: All keys are split by dots and categorized:
   - 1 part: Provider metadata (`name`, `description`, `default`)
   - 3 parts with `Service`: Service definitions
   - 4 parts with `alias`: Alias definitions
   - 5 parts with `attr`: Attribute definitions
   - Invalid keys throw `IOException`
3. **Load Defaults** (if `default = true` or `default = 1`):
   - Load `DefaultProviderAttrs.defaultProvAttrs`
   - Process default services with their aliases and attributes
4. **Process Config Services**:
   - For each service in config file:
     - Process aliases (add/delete/replace operations)
     - Process attributes (add/delete operations)
     - Create `ServiceDefinition` object
5. **Return List**: Return list of all `ServiceDefinition` objects

---

## Complete Examples

### Example 1: Basic Algorithm with Aliases
```properties
# Define the service
Service.MessageDigest.SHA-256 = com.ibm.crypto.plus.provider.MessageDigest$SHA256

# Add aliases including OIDs
MessageDigest.SHA-256.alias.add = OID.2.16.840.1.101.3.4.2.1, 2.16.840.1.101.3.4.2.1, SHA2, SHA-2, SHA256
```

### Example 2: Cipher with Multiple Variants
```properties
# Base cipher
Service.Cipher.AES = com.ibm.crypto.plus.provider.AESCipher

# Specific mode
Service.Cipher.AES/GCM/NoPadding = com.ibm.crypto.plus.provider.AESGCMCipher

# Key wrap variant with aliases
Cipher.AES_128/KW/NoPadding.alias.add = AESWrap_128, 2.16.840.1.101.3.4.1.5, OID.2.16.840.1.101.3.4.1.5
Service.Cipher.AES_128/KW/NoPadding = com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW_128
```

### Example 3: Service with Alias Operations
```properties
# Define service
Service.Cipher.AES = com.ibm.crypto.plus.provider.AESCipher

# Add some aliases
Cipher.AES.alias.add = Rijndael, AES-128, AES-192, AES-256

# Later, remove one
Cipher.AES.alias.delete = Rijndael

# Or replace all
Cipher.AES.alias.replace = AES-128, AES-192, AES-256
```

### Example 4: SecureRandom with Attributes
```properties
# Define secure random with aliases and attributes
SecureRandom.SHA256DRBG.alias.add = HASHDRBG, SHA2DRBG
SecureRandom.SHA256DRBG.attr.add.ThreadSafe = true
Service.SecureRandom.SHA256DRBG = com.ibm.crypto.plus.provider.HASHDRBG$SHA256DRBG
```

### Example 5: Using Default Provider Attributes
```properties
# Enable default attributes
default = true

# This will load all services from DefaultProviderAttrs.defaultProvAttrs
# Then you can override or add specific services

# Override a default service
Service.Cipher.AES = com.custom.provider.CustomAESCipher

# Add new aliases to a default service
Cipher.AES.alias.add = CustomAES

# Remove an alias from a default service
Cipher.AES.alias.delete = OldAlias
```

### Example 6: PQC (Post-Quantum Cryptography) Services
```properties
# Key Factory
KeyFactory.ML-KEM-768.alias.add = ML-KEM, ML_KEM_768, MLKEM768, OID.2.16.840.1.101.3.4.4.2, 2.16.840.1.101.3.4.4.2
Service.KeyFactory.ML-KEM-768 = com.ibm.crypto.plus.provider.PQCKeyFactory$MLKEM768

# Key Pair Generator
KeyPairGenerator.ML-DSA-65.alias.add = ML-DSA, ML_DSA_65, MLDSA65, OID.2.16.840.1.101.3.4.3.18, 2.16.840.1.101.3.4.3.18
Service.KeyPairGenerator.ML-DSA-65 = com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLDSA65

# KEM (Key Encapsulation Mechanism)
KEM.ML-KEM-768.alias.add = ML-KEM, ML_KEM_768, MLKEM768, OID.2.16.840.1.101.3.4.4.2, 2.16.840.1.101.3.4.4.2
Service.KEM.ML-KEM-768 = com.ibm.crypto.plus.provider.MLKEMImpl$MLKEM768

# Signature
Signature.ML-DSA-65.alias.add = ML-DSA, ML_DSA_65, MLDSA65, OID.2.16.840.1.101.3.4.3.18, 2.16.840.1.101.3.4.3.18
Service.Signature.ML-DSA-65 = com.ibm.crypto.plus.provider.PQCSignatureImpl$MLDSA65
```

---

## Naming Conventions

### Algorithm Names
- Use standard algorithm names (e.g., AES, RSA, SHA-256)
- Use hyphens for variants (e.g., SHA-256, SHA3-224)
- Use slashes for transformations (e.g., AES/GCM/NoPadding)
- Use underscores for specific key sizes (e.g., AES_128, ML-KEM-512)

### Class Names
- Use fully qualified package names
- Inner classes use `$` separator (e.g., `RSAKeyFactory$Legacy`)
- Variant implementations often use inner classes

### OID Formats
- Include both prefixed and non-prefixed versions
- Format: `OID.x.x.x.x` and `x.x.x.x`

---


### Standard Configuration (`ProviderDefAttrs.config`)
- **Full algorithm support**: Includes all algorithms
- **Legacy support**: Includes older algorithms for compatibility
- **Extended features**: XDH, EdDSA, PQC algorithms included
- **More key derivation options**: PBKDF2 with various hash functions

---

## Error Handling

The parser throws `IOException` for:
- **File not found**: Specified file path doesn't exist
- **Invalid key format**: Keys that don't match expected patterns (1, 3, 4, or 5 parts)
- **Missing required fields**: No `name` or `description` specified
- **Parse errors**: Issues loading properties file

Common issues:
- **Missing Service definition**: Alias or attribute defined before Service
- **Invalid class name**: Implementation class not found (runtime error)
- **Duplicate definitions**: Same service defined multiple times (last one wins)
- **Invalid operation**: Using unsupported operations (only add/delete/replace for aliases, add/delete for attributes)

---

## ServiceDefinition Class

The parser creates `ServiceDefinition` objects with:

```java
public class ServiceDefinition {
    private final String type;              // Service type (e.g., "Cipher")
    private final String algorithm;         // Algorithm name (e.g., "AES")
    private final String className;         // Implementation class
    private final List<String> aliases;     // List of alias names
    private final Map<String, String> attributes;  // Attribute key-value pairs
}
```

### Methods:
- `getType()`: Returns service type
- `getAlgorithm()`: Returns algorithm name
- `getClassName()`: Returns implementation class name
- `getAliases()`: Returns list of aliases
- `getAttributes()`: Returns map of attributes

---

## Best Practices

1. **Define Services First**: Always define the Service before aliases and attributes
2. **Group Related Services**: Use section comments to organize services by type
3. **Include OIDs**: Add both prefixed and non-prefixed OID formats
4. **Document Restrictions**: Use comments to explain FIPS or other restrictions
5. **Consistent Naming**: Follow naming conventions throughout the file
6. **Use Defaults Wisely**: Set `default = true` to inherit common services, then override as needed
7. **Order Matters**: For aliases, remember that add/delete/replace are processed in order
8. **Attribute Operations**: Use add for setting/updating, delete for removing

---

## Summary

The provider configuration format uses Java Properties syntax with specific key patterns:

| Parts | Pattern | Purpose | Example |
|-------|---------|---------|---------|
| 1 | `name` / `description` / `default` | Provider metadata | `name = test` |
| 3 | `Service.<Type>.<Algorithm>` | Service definition | `Service.Cipher.AES = com.ibm...` |
| 4 | `<Type>.<Algorithm>.alias.<op>` | Alias operations | `Cipher.AES.alias.add = Rijndael` |
| 5 | `<Type>.<Algorithm>.attr.<op>.<name>` | Attribute operations | `SecureRandom.SHA256DRBG.attr.add.ThreadSafe = true` |

**Alias Operations**: `add`, `delete`, `replace`  
**Attribute Operations**: `add`, `delete`

This format provides a flexible, property-based way to configure JCE providers with support for multiple algorithm names, OID mappings, service attributes, and inheritance from default configurations.