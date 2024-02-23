# Table Of Contents

- [Overview](#overview)
- [How to Build `OpenJCEPlus` and Java Native Interface Library](#how-to-build-openjceplus-and-java-native-interface-library)
- [Test Execution](#test-execution)
  - [Run All Tests](#run-all-tests)
  - [Run Single Test](#run-single-test)
- [OpenJCEPlus and OpenJCEPlusFIPS Provider SDK Installation](#openjceplus-and-openjceplusfips-provider-sdk-installation)
- [Features and Algorithms](#features-and-algorithms)
- [Contributions](#contributions)

# Overview

This project contains source code associated with the `OpenJCEPlus` and `OpenJCEPlusFIPS` cryptographic providers that can be used within a Java SDK. At this time, this project intends to only issue source code releases which will not include any binary distribution format. These cryptographic providers contain capabilities to support JCE cryptographic operations using the `Open Crypto Kit` cryptographic library.

**IMPORTANT NOTE:
Although this project uses the term "FIPS" in different code paths and naming conventions the code and binary files derived from this code CANNOT be
considered FIPS compliant. Achieving certified FIPS cryptography requires the underlying library binary to be FIPS certified for specific platforms
and architectures. Any cryptographic libraries developed must adhere to rigorous FIPS standards and should not be assumed to be available in any environment.
All environments and binaries must undergo the FIPS certification process with NIST to ensure compliance.**

This github branch can only be used with Java version 17.

## How to Build `OpenJCEPlus` and Java Native Interface Library

`OpenJCEPlus` and `OpenJCEPlusFIPS` providers are currently supported on the following architectures and operating system combinations as reported by `mvn --version` in the values `OS name` and `arch`:
| OS name                 | arch        |
| ----------------------- | ----------- |
| linux                   | amd64       |
| linux                   | s390x       |
| linux                   | ppc64le     |
| Windows Server 2022     | amd64       |
| AIX                     | ppc64       |
| Mac OS X*               | aarch64*    |
* Mac OS X currently is only able to compile and run tests using the `OpenJCEPlus` provider, not `OpenJCEPlusFIPS`. The provider `OpenJCEPlusFIPS` will not load.

Follow these steps to build the `OpenJCEPlus` and `OpenJCEPlusFIPS` providers along with a dependent Java Native Interface library. Keep in mind that `$PROJECT_HOME` can represent any directory on your
system and will be referred to as such in the subsequent instructions:

1. Create an OCK directory, for example:

    ```console
    mkdir $PROJECT_HOME/OCK
    ```

1. Extract the Java gskit SDK tar and gskit tar file into the directory previously created:

    ```console
    cd $PROJECT_HOME/OCK
    tar xvf jgsk_crypto_8_9_3_0_sdk.tar
    tar xvf jgsk_crypto_8_9_3_0.tar
    ```

1. Copy the OCK library referred to as ICC to the correct location:

   Create the `lib64` directory and copy the `libjgsk8iccs_64.so` library to that location:

   ```console
   mkdir $PROJECT_HOME/OCK/jgsk_sdk/lib64
   cp $PROJECT_HOME/OCK/libjgsk8iccs_64.so $PROJECT_HOME/OCK/jgsk_sdk/lib64
   ```

   On AIX copy the library to the `jgsk_sdk` directory **in addition** to the `lib64` directory above.

   ```console
   cp $PROJECT_HOME/OCK/libjgsk8iccs_64.so $PROJECT_HOME/OCK/jgsk_sdk
   ```

   On Mac:

   ```console
   mkdir $PROJECT_HOME/OCK/jgsk_crypto_sdk/jgsk_sdk/lib64
   cp $PROJECT_HOME/OCK/jgsk_crypto/libjgsk8iccs_64.so $PROJECT_HOME/OCK/jgsk_crypto_sdk/jgsk_sdk/lib64
   ```

1. Install `Maven` and place the command in your `PATH`. These instructions are OS dependant. It is recommended to make use of version `3.9.2`, although other versions of `Maven` are known to work.
You can test your installation by issuing `mvn --version`. For example:

    ```console
    $ mvn --version
    Apache Maven 3.9.2 (c9616018c7a021c1c39be70fb2843d6f5f9b8a1c)
    Maven home: /tools/apache-maven-3.9.2
    Java version: 1.8.0_361, vendor: IBM Corporation, runtime: /opt/ibm/sdks/jdk-17.0.5+8
    Default locale: en_US, platform encoding: ISO8859-1
    OS name: "aix", version: "7.2", arch: "ppc64", family: "unix"
    ```

1. Clone the `OpenJCEPlus` respository.

1. Change directory to the root directory where the `pom.xml` file exists.

    ```console
    cd OpenJCEPlus
    ```

1. Set your `JAVA_HOME` environment variable. This will be the SDK used to compile the project. You must set your JAVA_HOME value to Java version 17 when using code located in the `main` branch.

    ```console
    export JAVA_HOME="/opt/ibm/sdks/jdk-17.0.5+8"
    ```

1. Set the location of the variable `GSKIT_SDK` to the directory extracted in the above steps.

    ```console
    export GSKIT_HOME="$PROJECT_HOME/OCK/jgsk_sdk"
    ```

   On Mac:

   ```console
   export GSKIT_HOME="$PROJECT_HOME/OCK/jgsk_crypto_sdk/jgsk_sdk"
   ```

1. **(Only for Windows)** Some additional environment variables need to be set in Windows. There are certain header files and libraries that are required to build the `OpenJCEPlus` and `OpenJCEPlusFIPS` providers in a Windows environment and those files are found in the exported directories. It is assumed that you are running through a `CYGWIN` prompt.

    ```console
    export PATH=/cygdrive/c/Program\ Files\ \(x86\)/Windows\ Kits/10/bin/10.0.19041.0/x64/:/cygdrive/c/Program\ Files/Microsoft\ Visual\ Studio/2022/Professional/VC/Tools/MSVC/14.31.31103/bin/Hostx64/x64/:$PATH

    export INCLUDE="C:/Program Files (x86)/Windows Kits/10/include/10.0.19041.0/um/;C:/Program Files (x86)/Windows Kits/10/include/10.0.19041.0/shared/;C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC/14.31.31103/include/;C:/Program Files (x86)/Windows Kits/10/include/10.0.19041.0/ucrt/"

    export LIB="C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC/14.31.31103/lib/x64;C:/Program Files (x86)/Windows Kits/10/lib/10.0.19041.0/ucrt/x64;C:/Program Files (x86)/Windows Kits/10/lib/10.0.19041.0/um/x64"
    ```

    **NOTE 1**: You need to have installed `Microsoft Visual Studio` and `CYGWIN` on your machine.

    **NOTE 2**: You might have to adapt the exported environment variables, if the installation directory of `Visual Studio` is different on your machine, or the versions you have available for `Windows Kits` and `Visual Studio` are diffent (e.g., the `Windows Kits` version in the variables above is `10.0.19041.0`, but it might be different on your machine).

1. Compile the `OpenJCEPlus` and `OpenJCEPlusFIPS` providers along with the Java Native Interface library. This command intentionally skips test execution. See instructions below for [running tests](#Test-Execution).

    ```console
    mvn '-Dock.library.path=$PROJECT_HOME/OCK/' install -DskipTests
    ```

    On Mac:

    ```console
    mvn '-Dock.library.path=$PROJECT_HOME/OCK/jgsk_crypto' install -DskipTests
    ```

## Test Execution

Tests are available within the `OpenJCEPlus` repository. These Junit tests can be run in various ways including running individual tests or the entire test suite.

### Run all tests

On AIX you must set an additional setting for the `LIBPATH` environment variable:

```console
export LIBPATH="$PROJECT_HOME/OCK/:$PROJECT_HOME/OCK/jgsk_sdk"
```

On all platforms set the following environment variables and execute all the tests using `mvn`. You must set your JAVA_HOME value to Java version 17 when using code located in the `main` branch.

```console
export JAVA_HOME="$JAVA_INSTALL_DIRECTORY/jdk-17.0.5+8"
export GSKIT_HOME="$PROJECT_HOME/OCK/jgsk_sdk"
mvn '-Dock.library.path=$PROJECT_HOME/OCK/' test
```

**NOTE**: When using a JDK that doesn't have `OpenJCEPlus` bundled with it, you might notice a few warnings like `WARNING: Unknown module: openjceplus specified to --add-exports`. There is no need to worry as they do not affect execution of tests or the build itself.

### Run single test

On AIX you must set an additional setting for the `LIBPATH` environment variable:

```console
export LIBPATH="$PROJECT_HOME/OCK/:$PROJECT_HOME/OCK/jgsk_sdk"
```

On all platforms change to the OpenJCEPlus directory and set the following environment variables and execute a specific test name using `mvn`. You must set your JAVA_HOME value to Java version 17 when using code located in the `main` branch.

```console
cd OpenJCEPlus
export JAVA_HOME="$JAVA_INSTALL_DIRECTORY/jdk-17.0.5+8"
export GSKIT_HOME="$PROJECT_HOME/OCK/jgsk_sdk"
mvn '-Dock.library.path=$PROJECT_HOME/OCK/' test -Dtest=TestClassname
```

## OpenJCEPlus and OpenJCEPlusFIPS Provider SDK Installation

1. Modify your `java.security` file located in the `$JAVA_HOME/conf/security` directory by adding one of the following providers. The value `XX`
below represents your desired preference order.

    ```console
    security.provider.XX=com.ibm.crypto.plus.provider.OpenJCEPlusFIPS
    security.provider.XX=com.ibm.crypto.plus.provider.OpenJCEPlus
    ```

1. Execute your application specifying the `openjceplus.jar`, the location of the OCK library, and the location of the jgskit library as follows.

    ```console
    -Xbootclasspath/a:$ANYDIRECTORY/openjceplus.jar
    ```

    ```console
    '-Dock.library.path=$PROJECT_HOME/OCK/'
    ```

    ```console
    -Djgskit.library.path=$ANYDIRECTORY
    ```

# Features And Algorithms

The following algorothms are registered by the OpenJCEPlus and OpenJCEPlusFIPS providers.

| Algorithm Type            | Algorithm Name             | OpenJCEPlusFIPS | OpenJCEPlus  |
| --------------------------|----------------------------|-----------------|--------------|
AlgorithmParameterGenerator | CCM                        |X                |X             |
AlgorithmParameterGenerator | DSA                        |                 |X             |
AlgorithmParameterGenerator | DiffieHellman              |X                |X             |
AlgorithmParameterGenerator | EC                         |X                |X             |
AlgorithmParameterGenerator | GCM                        |X                |X             |
AlgorithmParameters         | AES                        |X                |X             |
AlgorithmParameters         | CCM                        |X                |X             |
AlgorithmParameters         | ChaCha20-Poly1305          |                 |X             |
AlgorithmParameters         | DESede                     |                 |X             |
AlgorithmParameters         | DSA                        |X                |X             |
AlgorithmParameters         | DiffieHellman              |X                |X             |
AlgorithmParameters         | EC                         |X                |X             |
AlgorithmParameters         | GCM                        |X                |X             |
AlgorithmParameters         | OAEP                       |X                |X             |
AlgorithmParameters         | RSAPSS                     |X                |X             |
Cipher                      | AES                        |X                |X             |
Cipher                      | AES/CCM/NoPadding          |X                |X             |
Cipher                      | AES/GCM/NoPadding          |X                |X             |
Cipher                      | ChaCha20                   |                 |X             |
Cipher                      | ChaCha20-Poly1305          |                 |X             |
Cipher                      | DESede                     |                 |X             |
Cipher                      | RSA                        |                 |X             |
KeyAgreement                | DiffieHellman              |X                |X             |
KeyAgreement                | ECDH                       |X                |X             |
KeyAgreement                | X25519                     |                 |X             |
KeyAgreement                | X448                       |                 |X             |
KeyAgreement                | XDH                        |                 |X             |
KeyFactory                  | DSA                        |X                |X             |
KeyFactory                  | DiffieHellman              |X                |X             |
KeyFactory                  | EC                         |X                |X             |
KeyFactory                  | Ed25519                    |                 |X             |
KeyFactory                  | Ed448                      |                 |X             |
KeyFactory                  | EdDSA                      |                 |X             |
KeyFactory                  | RSA                        |X                |X             |
KeyFactory                  | RSAPSS                     |X                |X             |
KeyFactory                  | X25519                     |                 |X             |
KeyFactory                  | X448                       |                 |X             |
KeyFactory                  | XDH                        |                 |X             |
KeyGenerator                | AES                        |X                |X             |
KeyGenerator                | ChaCha20                   |                |X             |
KeyGenerator                | DESede                     |                 |X             |
KeyGenerator                | HmacMD5                    |                 |X             |
KeyGenerator                | HmacSHA1                   |                 |X             |
KeyGenerator                | HmacSHA224                 |X                |X             |
KeyGenerator                | HmacSHA256                 |X                |X             |
KeyGenerator                | HmacSHA3-224               |X                |X             |
KeyGenerator                | HmacSHA3-256               |X                |X             |
KeyGenerator                | HmacSHA3-384               |X                |X             |
KeyGenerator                | HmacSHA3-512               |X                |X             |
KeyGenerator                | HmacSHA384                 |X                |X             |
KeyGenerator                | HmacSHA512                 |X                |X             |
KeyGenerator                | SunTls12KeyMaterial        |X                |X             |
KeyGenerator                | SunTls12MasterSecret       |X                |X             |
KeyGenerator                | SunTls12Prf                |X                |X             |
KeyGenerator                | SunTls12RsaPremasterSecret |X                |X             |
KeyGenerator                | SunTlsKeyMaterial          |X                |X             |
KeyGenerator                | SunTlsMasterSecret         |X                |X             |
KeyGenerator                | SunTlsPrf                  |X                |X             |
KeyGenerator                | SunTlsRsaPremasterSecret   |X                |X             |
KeyGenerator                | kda-hkdf-with-sha1         |                 |X             |
KeyGenerator                | kda-hkdf-with-sha224       |X                |X             |
KeyGenerator                | kda-hkdf-with-sha256       |X                |X             |
KeyGenerator                | kda-hkdf-with-sha384       |X                |X             |
KeyGenerator                | kda-hkdf-with-sha512       |X                |X             |
KeyPairGenerator            | DSA                        |                 |X             |
KeyPairGenerator            | DiffieHellman              |X                |X             |
KeyPairGenerator            | EC                         |X                |X             |
KeyPairGenerator            | Ed25519                    |                 |X             |
KeyPairGenerator            | Ed448                      |                 |X             |
KeyPairGenerator            | EdDSA                      |                 |X             |
KeyPairGenerator            | RSA                        |X                |X             |
KeyPairGenerator            | RSAPSS                     |X                |X             |
KeyPairGenerator            | X25519                     |                 |X             |
KeyPairGenerator            | X448                       |                 |X             |
KeyPairGenerator            | XDH                        |                 |X             |
Mac                         | HmacMD5                    |                 |X             |
Mac                         | HmacSHA1                   |                 |X             |
Mac                         | HmacSHA224                 |X                |X             |
Mac                         | HmacSHA256                 |X                |X             |
Mac                         | HmacSHA3-224               |X                |X             |
Mac                         | HmacSHA3-256               |X                |X             |
Mac                         | HmacSHA3-384               |X                |X             |
Mac                         | HmacSHA3-512               |X                |X             |
Mac                         | HmacSHA384                 |X                |X             |
Mac                         | HmacSHA512                 |X                |X             |
MessageDigest               | MD5                        |X                |X             |
MessageDigest               | SHA-1                      |X                |X             |
MessageDigest               | SHA-224                    |X                |X             |
MessageDigest               | SHA-256                    |X                |X             |
MessageDigest               | SHA-384                    |X                |X             |
MessageDigest               | SHA-512                    |X                |X             |
MessageDigest               | SHA-512/224                |X                |X             |
MessageDigest               | SHA-512/256                |X                |X             |
MessageDigest               | SHA3-224                   |X                |X             |
MessageDigest               | SHA3-256                   |X                |X             |
MessageDigest               | SHA3-384                   |X                |X             |
MessageDigest               | SHA3-512                   |X                |X             |
SecretKeyFactory            | AES                        |X                |X             |
SecretKeyFactory            | ChaCha20                   |                 |X             |
SecretKeyFactory            | DESede                     |                 |X             |
SecureRandom                | SHA256DRBG                 |X                |X             |
SecureRandom                | SHA512DRBG                 |X                |X             |
Signature                   | Ed25519                    |                 |X             |
Signature                   | Ed448                      |                 |X             |
Signature                   | EdDSA                      |X                |X             |
Signature                   | NONEwithDSA                |X                |X             |
Signature                   | NONEwithECDSA              |X                |X             |
Signature                   | NONEwithRSA                |X                |X             |
Signature                   | RSAPSS                     |X                |X             |
Signature                   | RSAforSSL                  |X                |X             |
Signature                   | SHA1withDSA                |                 |X             |
Signature                   | SHA1withECDSA              |                 |X             |
Signature                   | SHA1withRSA                |X                |X             |
Signature                   | SHA224withDSA              |X                |X             |
Signature                   | SHA224withECDSA            |X                |X             |
Signature                   | SHA224withRSA              |X                |X             |
Signature                   | SHA256withDSA              |X                |X             |
Signature                   | SHA256withECDSA            |X                |X             |
Signature                   | SHA256withRSA              |X                |X             |
Signature                   | SHA3-224withDSA            |                 |X             |
Signature                   | SHA3-224withECDSA          |                 |X             |
Signature                   | SHA3-224withRSA            |                 |X             |
Signature                   | SHA3-256withDSA            |                 |X             |
Signature                   | SHA3-256withECDSA          |                 |X             |
Signature                   | SHA3-256withRSA            |                 |X             |
Signature                   | SHA3-384withDSA            |                 |X             |
Signature                   | SHA3-384withECDSA          |                 |X             |
Signature                   | SHA3-384withRSA            |                 |X             |
Signature                   | SHA3-512withDSA            |                 |X             |
Signature                   | SHA3-512withECDSA          |                 |X             |
Signature                   | SHA3-512withRSA            |                 |X             |
Signature                   | SHA384withECDSA            |X                |X             |
Signature                   | SHA384withRSA              |X                |X             |
Signature                   | SHA512withECDSA            |X                |X             |
Signature                   | SHA512withRSA              |X                |X             |

# Contributions

The following contribution guidelines should be followed:

1. Code should be styled according to the included [style.xml](style.xml) eclipse rules.

1. A pull request should be sent for review only after the github action associated with this repository is automatically executed when a pull request is created.
