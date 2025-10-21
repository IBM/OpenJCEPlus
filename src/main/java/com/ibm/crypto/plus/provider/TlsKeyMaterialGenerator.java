/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.internal.spec.TlsKeyMaterialSpec;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.LABEL_CLIENT_WRITE_KEY;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.LABEL_IV_BLOCK;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.LABEL_KEY_EXPANSION;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.LABEL_SERVER_WRITE_KEY;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.SSL3_CONST;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.concat;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.doTLS10PRF;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.doTLS12PRF;

/**
 * KeyGenerator implementation for the SSL/TLS master secret derivation.
 */
public final class TlsKeyMaterialGenerator extends KeyGeneratorSpi {

    private final static String MSG = "TlsKeyMaterialGenerator must be "
            + "initialized using a TlsKeyMaterialParameterSpec";

    private OpenJCEPlusProvider provider = null;
    private sun.security.internal.spec.TlsKeyMaterialParameterSpec spec;

    private int protocolVersion;

    /**
     * Verify the JCE framework in the constructor.
     * 
     * @exception SecurityException
     *                if fails to verify the JCE framework.
     */
    public TlsKeyMaterialGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof sun.security.internal.spec.TlsKeyMaterialParameterSpec == false) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (sun.security.internal.spec.TlsKeyMaterialParameterSpec) params;
        if ("RAW".equals(spec.getMasterSecret().getFormat()) == false) {
            throw new InvalidAlgorithmParameterException("Key format must be RAW");
        }
        protocolVersion = (spec.getMajorVersion() << 8) | spec.getMinorVersion();
        if ((protocolVersion < 0x0300) || (protocolVersion > 0x0303)) {
            throw new InvalidAlgorithmParameterException("Only SSL 3.0, TLS 1.0/1.1/1.2 supported");
        }
    }

    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected SecretKey engineGenerateKey() {
        if (spec == null) {
            throw new IllegalStateException("TlsKeyMaterialGenerator must be initialized");
        }
        try {
            return engineGenerateKey0();
        } catch (GeneralSecurityException e) {
            throw new ProviderException(e);
        }
    }

    private SecretKey engineGenerateKey0() throws GeneralSecurityException {
        byte[] masterSecret = spec.getMasterSecret().getEncoded();

        byte[] clientRandom = spec.getClientRandom();
        byte[] serverRandom = spec.getServerRandom();

        SecretKey clientMacKey = null;
        SecretKey serverMacKey = null;
        SecretKey clientCipherKey = null;
        IvParameterSpec clientIv = null;
        SecretKey serverCipherKey = null;
        IvParameterSpec serverIv = null;

        int macLength = spec.getMacKeyLength();
        int expandedKeyLength = spec.getExpandedCipherKeyLength();
        boolean isExportable = (expandedKeyLength != 0);
        int keyLength = spec.getCipherKeyLength();
        int ivLength = spec.getIvLength();

        int keyBlockLen = macLength + keyLength + (isExportable ? 0 : ivLength);
        keyBlockLen <<= 1;
        byte[] keyBlock = new byte[keyBlockLen];

        // These may be used again later for exportable suite calculations.
        MessageDigest md5 = null;
        MessageDigest sha = null;

        // TLS or FIPS ciphers at SSL 3.0 or TLS
        // FIPS Ciphers - "SSL_RSA_FIPS_WITH_DES_CBC_SHA" or
        // "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" - SSLv3/TLS1.0 only
        // See
        // http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
        // generate key block
        if (protocolVersion >= 0x0303) {
            // TLS 1.2
            byte[] seed = concat(serverRandom, clientRandom);
            keyBlock = doTLS12PRF(provider, masterSecret, LABEL_KEY_EXPANSION, seed, keyBlockLen,
                    spec.getPRFHashAlg(), spec.getPRFHashLength(), spec.getPRFBlockSize());
            // fill intermediate arrays with 0x00 - FIPS requirement to reset
            // arrays that
            // got filled with random bytes from random.
            Arrays.fill(seed, (byte) 0x00);
        } else if (protocolVersion >= 0x0301) {
            // TLS 1.0/1.1
            md5 = MessageDigest.getInstance("MD5", provider);
            sha = MessageDigest.getInstance("SHA-1", provider);
            byte[] seed = concat(serverRandom, clientRandom);
            keyBlock = doTLS10PRF(masterSecret, LABEL_KEY_EXPANSION, seed, keyBlockLen, md5, sha);
            // fill intermediate arrays with 0x00 - FIPS requirement to reset
            // arrays that
            // got filled with random bytes from random.
            Arrays.fill(seed, (byte) 0x00);
        } else {
            // SSL
            md5 = MessageDigest.getInstance("MD5", provider);
            sha = MessageDigest.getInstance("SHA-1", provider);
            keyBlock = new byte[keyBlockLen];

            byte[] tmp = new byte[20];
            for (int i = 0, remaining = keyBlockLen; remaining > 0; i++, remaining -= 16) {

                sha.update(SSL3_CONST[i]);
                sha.update(masterSecret);
                sha.update(serverRandom);
                sha.update(clientRandom);
                sha.digest(tmp, 0, 20);

                md5.update(masterSecret);
                md5.update(tmp);

                if (remaining >= 16) {
                    md5.digest(keyBlock, i << 4, 16);
                } else {
                    md5.digest(tmp, 0, 16);
                    System.arraycopy(tmp, 0, keyBlock, i << 4, remaining);
                }
            }
            // fill intermediate arrays with 0x00 - FIPS requirement to reset
            // arrays that
            // got filled with random bytes from random.
            Arrays.fill(tmp, (byte) 0x00);
        }

        // partition keyblock into individual secrets

        int ofs = 0;



        if (macLength != 0) {
            byte[] tmp = new byte[macLength];
            // mac keys
            System.arraycopy(keyBlock, ofs, tmp, 0, macLength);
            ofs += macLength;
            clientMacKey = new SecretKeySpec(tmp, "Mac");

            System.arraycopy(keyBlock, ofs, tmp, 0, macLength);
            ofs += macLength;
            serverMacKey = new SecretKeySpec(tmp, "Mac");
            // fill intermediate arrays with 0x00 - FIPS requirement to
            // reset arrays that
            // got filled with random bytes from random.
            Arrays.fill(tmp, (byte) 0x00);
        }

        if (keyLength == 0) { // SSL_RSA_WITH_NULL_* ciphersuites
            SecretKey sKey = new TlsKeyMaterialSpec(clientMacKey, serverMacKey);
            // fill intermediate arrays with 0x00 - FIPS requirement to
            // reset arrays that
            // got filled with random bytes from random or arrays containing
            // key material.
            Arrays.fill(masterSecret, (byte) 0x00);
            Arrays.fill(clientRandom, (byte) 0x00);
            Arrays.fill(serverRandom, (byte) 0x00);

            return sKey;
        }

        String alg = spec.getCipherAlgorithm();

        // cipher keys
        byte[] clientKeyBytes = new byte[keyLength];
        System.arraycopy(keyBlock, ofs, clientKeyBytes, 0, keyLength);
        ofs += keyLength;

        byte[] serverKeyBytes = new byte[keyLength];
        System.arraycopy(keyBlock, ofs, serverKeyBytes, 0, keyLength);
        ofs += keyLength;

        if (isExportable == false) {
            // cipher keys
            clientCipherKey = new SecretKeySpec(clientKeyBytes, alg);
            serverCipherKey = new SecretKeySpec(serverKeyBytes, alg);

            // IV keys if needed.
            if (ivLength != 0) {
                byte[] tmp = new byte[ivLength];

                System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
                ofs += ivLength;
                clientIv = new IvParameterSpec(tmp);

                System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
                ofs += ivLength;
                serverIv = new IvParameterSpec(tmp);
                // fill intermediate arrays with 0x00 - FIPS requirement to
                // reset arrays that
                // got filled with random bytes from random or arrays containing
                // key material.
                Arrays.fill(tmp, (byte) 0x00);
            }
        } else {
            // if exportable suites, calculate the alternate
            // cipher key expansion and IV generation
            if (protocolVersion >= 0x0302) {
                // TLS 1.1+
                throw new ProviderException("Internal Error:  TLS 1.1+ should not be negotiating"
                        + "exportable ciphersuites");
            } else if (protocolVersion == 0x0301) {
                // TLS 1.0
                byte[] seed = concat(clientRandom, serverRandom);

                byte[] tmp = doTLS10PRF(clientKeyBytes, LABEL_CLIENT_WRITE_KEY, seed,
                        expandedKeyLength, md5, sha);
                clientCipherKey = new SecretKeySpec(tmp, alg);

                tmp = doTLS10PRF(serverKeyBytes, LABEL_SERVER_WRITE_KEY, seed, expandedKeyLength,
                        md5, sha);
                serverCipherKey = new SecretKeySpec(tmp, alg);
                // fill intermediate arrays with 0x00 - FIPS requirement to
                // reset arrays that
                // got filled with random bytes from random or arrays containing
                // key material.
                Arrays.fill(tmp, (byte) 0x00);

                if (ivLength != 0) {
                    tmp = new byte[ivLength];
                    byte[] block = doTLS10PRF(null, LABEL_IV_BLOCK, seed, ivLength << 1, md5, sha);
                    System.arraycopy(block, 0, tmp, 0, ivLength);
                    clientIv = new IvParameterSpec(tmp);
                    System.arraycopy(block, ivLength, tmp, 0, ivLength);
                    serverIv = new IvParameterSpec(tmp);
                    // fill intermediate arrays with 0x00 - FIPS requirement to
                    // reset arrays that
                    // got filled with random bytes from random or arrays
                    // containing key material.
                    Arrays.fill(block, (byte) 0x00);
                }
                // fill intermediate arrays with 0x00 - FIPS requirement to
                // reset arrays that
                // got filled with random bytes from random or arrays containing
                // key material.
                Arrays.fill(seed, (byte) 0x00);

            } else {
                // SSLv3
                byte[] tmp = new byte[expandedKeyLength];

                md5.update(clientKeyBytes);
                md5.update(clientRandom);
                md5.update(serverRandom);
                System.arraycopy(md5.digest(), 0, tmp, 0, expandedKeyLength);
                clientCipherKey = new SecretKeySpec(tmp, alg);

                md5.update(serverKeyBytes);
                md5.update(serverRandom);
                md5.update(clientRandom);
                System.arraycopy(md5.digest(), 0, tmp, 0, expandedKeyLength);
                serverCipherKey = new SecretKeySpec(tmp, alg);
                // fill intermediate arrays with 0x00 - FIPS requirement to
                // reset arrays that
                // got filled with random bytes from random or arrays containing
                // key material.
                Arrays.fill(tmp, (byte) 0x00);

                if (ivLength != 0) {
                    tmp = new byte[ivLength];

                    md5.update(clientRandom);
                    md5.update(serverRandom);
                    System.arraycopy(md5.digest(), 0, tmp, 0, ivLength);
                    clientIv = new IvParameterSpec(tmp);

                    md5.update(serverRandom);
                    md5.update(clientRandom);
                    System.arraycopy(md5.digest(), 0, tmp, 0, ivLength);
                    serverIv = new IvParameterSpec(tmp);
                    // fill intermediate arrays with 0x00 - FIPS requirement to
                    // reset arrays that
                    // got filled with random bytes from random or arrays
                    // containing key material.
                    Arrays.fill(tmp, (byte) 0x00);
                }
            }
        }

        // fill intermediate arrays with 0x00 - FIPS requirement to reset arrays
        // that
        // got filled with random bytes from random.
        Arrays.fill(masterSecret, (byte) 0x00);
        Arrays.fill(clientRandom, (byte) 0x00);
        Arrays.fill(serverRandom, (byte) 0x00);
        Arrays.fill(clientKeyBytes, (byte) 0x00);
        Arrays.fill(serverKeyBytes, (byte) 0x00);
        Arrays.fill(keyBlock, (byte) 0x00);

        SecretKey sKey = new TlsKeyMaterialSpec(clientMacKey, serverMacKey, clientCipherKey,
                clientIv, serverCipherKey, serverIv);

        return sKey;
    }

}
