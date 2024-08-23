/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.LABEL_EXTENDED_MASTER_SECRET;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.LABEL_MASTER_SECRET;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.SSL3_CONST;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.concat;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.doTLS10PRF;
import static com.ibm.crypto.plus.provider.TlsPrfGenerator.doTLS12PRF;

/**
 * KeyGenerator implementation for the SSL/TLS master secret derivation.
 */
public final class TlsMasterSecretGenerator extends KeyGeneratorSpi {

    private final static String MSG = "TlsMasterSecretGenerator must be "
            + "initialized using a TlsMasterSecretParameterSpec";

    private OpenJCEPlusProvider provider = null;
    private sun.security.internal.spec.TlsMasterSecretParameterSpec spec;

    private int protocolVersion;

    public TlsMasterSecretGenerator(OpenJCEPlusProvider provider) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof sun.security.internal.spec.TlsMasterSecretParameterSpec == false) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (sun.security.internal.spec.TlsMasterSecretParameterSpec) params;

        if ("RAW".equals(spec.getPremasterSecret().getFormat()) == false) {
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
            throw new IllegalStateException("TlsMasterSecretGenerator must be initialized");
        }
        SecretKey premasterKey = spec.getPremasterSecret();

        byte[] premaster = premasterKey.getEncoded();

        int premasterMajor, premasterMinor;
        if (premasterKey.getAlgorithm().equals("TlsRsaPremasterSecret")) {
            // RSA
            premasterMajor = premaster[0] & 0xff;
            premasterMinor = premaster[1] & 0xff;
        } else {
            // DH, KRB5, others
            premasterMajor = -1;
            premasterMinor = -1;
        }

        try {
            byte[] master;

            // TLS or FIPS ciphers at SSL 3.0 or TLS
            // FIPS Ciphers - "SSL_RSA_FIPS_WITH_DES_CBC_SHA" or "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
            // See http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html

            if (protocolVersion >= 0x0301) {

                byte[] label;
                byte[] seed;
                byte[] extendedMasterSecretSessionHash = spec.getExtendedMasterSecretSessionHash();

                if (extendedMasterSecretSessionHash.length != 0) {
                    label = LABEL_EXTENDED_MASTER_SECRET;
                    seed = extendedMasterSecretSessionHash;
                } else {

                    byte[] clientRandom = spec.getClientRandom();
                    byte[] serverRandom = spec.getServerRandom();
                    label = LABEL_MASTER_SECRET;
                    seed = concat(clientRandom, serverRandom);
                    if (clientRandom != null) {
                        Arrays.fill(clientRandom, (byte) 0x00);
                    }
                    if (serverRandom != null) {
                        Arrays.fill(serverRandom, (byte) 0x00);
                    }

                }

                //byte[] seed = concat(clientRandom, serverRandom);
                master = ((protocolVersion >= 0x0303)
                        ? doTLS12PRF(provider, premaster, label, seed, 48, spec.getPRFHashAlg(),
                                spec.getPRFHashLength(), spec.getPRFBlockSize())
                        : doTLS10PRF(provider, premaster, label, seed, 48));
                // fill intermediate arrays with 0x00 - FIPS requirement to
                // reset arrays that
                // got filled with random bytes from random or arrays containing
                // key material.
                Arrays.fill(seed, (byte) 0x00);

            } else {
                master = new byte[48];
                MessageDigest md5 = MessageDigest.getInstance("MD5", provider);
                MessageDigest sha = MessageDigest.getInstance("SHA-1", provider);
                byte[] clientRandom = spec.getClientRandom();
                byte[] serverRandom = spec.getServerRandom();

                byte[] tmp = new byte[20];
                for (int i = 0; i < 3; i++) {
                    sha.update(SSL3_CONST[i]);
                    sha.update(premaster);
                    sha.update(clientRandom);
                    sha.update(serverRandom);
                    sha.digest(tmp, 0, 20);

                    md5.update(premaster);
                    md5.update(tmp);
                    md5.digest(master, i << 4, 16);
                }
                // fill intermediate arrays with 0x00 - FIPS requirement to
                // reset arrays that
                // got filled with random bytes from random or arrays containing
                // key material.
                Arrays.fill(tmp, (byte) 0x00);
                if (clientRandom != null) {
                    Arrays.fill(clientRandom, (byte) 0x00);
                }
                if (serverRandom != null) {
                    Arrays.fill(serverRandom, (byte) 0x00);
                }

            }
            SecretKey sKey = new TlsMasterSecretKey(master, premasterMajor, premasterMinor);
            // fill intermediate arrays with 0x00 - FIPS requirement to reset
            // arrays that
            // got filled with random bytes from random.
            if (master != null) {
                Arrays.fill(master, (byte) 0x00);
            }

            return sKey;
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        } catch (DigestException e) {
            throw new ProviderException(e);
        } finally {
            // fill intermediate arrays with 0x00 - FIPS requirement to reset
            // arrays that
            // got filled with random bytes from random.
            if (premaster != null) {
                Arrays.fill(premaster, (byte) 0x00);
            }
        }
    }

    private static final class TlsMasterSecretKey
            implements sun.security.internal.interfaces.TlsMasterSecret {
        private static final long serialVersionUID = -2482619999063672417L;

        private byte[] key;
        private final int majorVersion, minorVersion;

        TlsMasterSecretKey(byte[] key, int majorVersion, int minorVersion) {
            // this.key = key;
            this.key = (key == null) ? null : key.clone();
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }

        public int getMajorVersion() {
            return majorVersion;
        }

        public int getMinorVersion() {
            return minorVersion;
        }

        public String getAlgorithm() {
            return "TlsMasterSecret";
        }

        public String getFormat() {
            return "RAW";
        }

        public byte[] getEncoded() {
            return key.clone();
        }

    }

}
