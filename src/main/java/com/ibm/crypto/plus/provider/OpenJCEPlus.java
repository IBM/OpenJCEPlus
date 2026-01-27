/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKContext;
import com.ibm.crypto.plus.provider.ock.OCKException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.HashMap;
import java.util.Map;

public final class OpenJCEPlus extends OpenJCEPlusProvider {

    private static final long serialVersionUID = -1610967128950682479L;

    private static final String info = "OpenJCEPlus Provider implements the following:\n"
            + "Algorithm parameter                : AES, ChaCha20, ChaCha20-Poly1305, DESede, DiffieHellman, DSA, EC, XEC, GCM, CCM, OAEP, RSAPSS\n"
            + "                                       PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256\n"
            + "                                       PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256\n"
            + "                                       PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256, PBEWithHmacSHA512/224AndAES_128, PBEWithHmacSHA512/224AndAES_256\n"
            + "                                       PBEWithHmacSHA512/256AndAES_128, PBEWithHmacSHA512/256AndAES_256\n"                                     
            + "Algorithm parameter generator      :  DiffieHellman, DSA, EC, XEC, GCM, CCM\n"
            + "Cipher algorithms                  : AES, ChaCha20, ChaCha20-Poly1305, DESede, RSA\n"
            + "                                       PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256\n"
            + "                                       PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256\n"
            + "                                       PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256, PBEWithHmacSHA512/224AndAES_128, PBEWithHmacSHA512/224AndAES_256\n"
            + "                                       PBEWithHmacSHA512/256AndAES_128, PBEWithHmacSHA512/256AndAES_256\n"            
            + "Key agreement algorithms           : DiffieHellman, ECDH, XDH\n"
            + "Key Encapsulation Mechanisms       : ML-KEM-512, ML-KEM-768, ML-KEM-1024\n"
            + "Key factory                        : DiffieHellman, DSA, EC, XEC,  RSA, RSAPSS, ML-KEM-512, ML-KEM-768, ML-KEM-1024\n"
            + "Key generator                      : AES, ChaCha20, DESede, HmacMD5, HmacSHA1, HmacSHA224,\n"
            + "                                       HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512,\n"
            + "                                       HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512,\n"
            + "                                       kda-hkdf-witH-sha1, kda-hkdf-with-sha224,\n"
            + "                                       kda-hkdf-with-sha256, kda-hkdf-with-sha384,\n"
            + "                                       kda-hkdf-with-sha512\n"
            + "Key pair generator                 : DiffieHellman, DSA, EC, XEC, RSA, ML-DSA-44, ML-DSA-65, ML-DSA-87,\n"
            + "                                       ML-KEM-512, ML-KEM-768, ML-KEM-1024\n"
            + "Message authentication code (MAC)  : HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512\n"
            + "                                       , HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512\n"
            + "Message digest                     : MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512\n"
            + "Secret key factory                 : AES, ChaCha20, DESede, PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA224, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512\n"
            + "                                       PBKDF2WithHmacSHA512/224, PBKDF2WithHmacSHA512/256\n"
            + "                                       PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256\n"
            + "                                       PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256\n"
            + "                                       PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256, PBEWithHmacSHA512/224AndAES_128, PBEWithHmacSHA512/224AndAES_256\n"
            + "                                       PBEWithHmacSHA512/256AndAES_128, PBEWithHmacSHA512/256AndAES_256\n"              
            + "Secure random                      : HASHDRBG, SHA256DRBG, SHA512DRBG\n"
            + "Signature algorithms               : NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA,\n"
            + "                                       SHA3-224withDSA, SHA3-256withDSA, SHA3-384withDSA, SHA3-512withDSA,\n"
            + "                                       NONEwithECDSA, SHA1withECDSA, SHA224withECDSA,\n"
            + "                                       SHA256withECDSA, SHA384withECDSA, SHA512withECDSA,\n"
            + "                                       SHA3-224withECDSA, SHA3-256withECDSA, SHA3-384withECDSA, SHA3-512withECDSA,\n"
            + "                                       NONEwithRSA, SHA1withRSA, SHA224withRSA,\n"
            + "                                       SHA256withRSA, SHA384withRSA, SHA512withRSA, RSAPSS, Ed25519, Ed448,\n"
            + "                                       SHA3-224withRSA, SHA3-256withRSA, SHA3-384withRSA, SHA3-512withRSA,\n"
            + "                                       ML_DSA_44, ML_DSA_65, ML_DSA_87\n";


    private static final String OID_PKCS3 = "1.2.840.113549.1.3.1";

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile OpenJCEPlus instance;

    private static boolean ockInitialized = false;
    private static OCKContext ockContext;
    private static Map<String, String> attrs;

    public OpenJCEPlus() {
        super("OpenJCEPlus", info);

        if (debug != null) {
            debug.println("New OpenJCEPlus instance");
        }

        final OpenJCEPlusProvider jce = this;

        // Do java OCK initialization which includes loading native code
        // Don't do this in the static initializer because it might
        // be necessary for an applet running in a browser to grant
        // access rights beforehand.
        if (!ockInitialized) {
            initializeContext();
        }
        registerAlgorithms(jce);

        if (instance == null) {
            instance = this;
        }

        if (debug != null) {
            debug.println("OpenJCEPlus Build-Level: " + getDebugDate(this.getClass().getName()));
            debug.println("OpenJCEPlus library build date: " + OCKContext.getLibraryBuildDate());
            try {
                debug.println("OpenJCEPlus dependent library version: " + ockContext.getOCKVersion());
                debug.println("OpenJCEPlus dependent library path: " + ockContext.getOCKInstallPath());
            } catch (Throwable t) {
                t.printStackTrace(System.out);
            }
        }
    }

    private void registerAlgorithms(Provider jce) {

        String[] aliases = null;
        /* =======================================================================
         * Algorithm Parameter engines
         * =======================================================================
         */
        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "AES",
                "com.ibm.crypto.plus.provider.AESParameters", aliases));

        aliases = new String[] {"TripleDES", "3DES"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "DESede",
                "com.ibm.crypto.plus.provider.DESedeParameters", aliases));

        aliases = new String[] {"DH", "OID." + OID_PKCS3, OID_PKCS3};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "DiffieHellman",
                "com.ibm.crypto.plus.provider.DHParameters", aliases));

        aliases = new String[] {"OID.1.2.840.10040.4.1", "1.2.840.10040.4.1", "OID.1.3.14.3.2.12",
                "1.3.14.3.2.12"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "DSA",
                "com.ibm.crypto.plus.provider.DSAParameters", aliases));

        aliases = new String[] {"EllipticCurve", "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "EC",
                "com.ibm.crypto.plus.provider.ECParameters", aliases));

        aliases = new String[] {"AESGCM"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "GCM",
                "com.ibm.crypto.plus.provider.GCMParameters", aliases));

        aliases = new String[] {"AESCCM"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "CCM",
                "com.ibm.crypto.plus.provider.CCMParameters", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "OAEP",
                "com.ibm.crypto.plus.provider.OAEPParameters", aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA1AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA1AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA1AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA1AndAES_256", aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA224AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA224AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA224AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA224AndAES_256", aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA256AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA256AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA256AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA256AndAES_256", aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA384AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA384AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA384AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA384AndAES_256", aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA512AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA512AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA512AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA512AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA512/224AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA512_224AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA512/224AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA512_224AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA512/256AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA512_256AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "PBEWithHmacSHA512/256AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Parameters$HmacSHA512_256AndAES_256", aliases));
        
        /*aliases = null;
        putService(new OpenJCEPlusService(jce,
        "AlgorithmParameters",
        "ChaCha20",
        "com.ibm.crypto.plus.provider.ChaCha20Parameters",
        aliases)); */

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "ChaCha20-Poly1305",
                "com.ibm.crypto.plus.provider.ChaCha20Poly1305Parameters", aliases));

        /* =======================================================================
         * Algorithm parameter generation engines
         * =======================================================================
         */
        aliases = new String[] {"DH", "OID." + OID_PKCS3, OID_PKCS3};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameterGenerator", "DiffieHellman",
                "com.ibm.crypto.plus.provider.DHParameterGenerator", aliases));
        aliases = new String[] {"RSA-PSS", "RSASSA-PSS", "RSASA-PSS"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameters", "RSAPSS",
                "com.ibm.crypto.plus.provider.PSSParameters", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameterGenerator", "DSA",
                "com.ibm.crypto.plus.provider.DSAParameterGenerator", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "AlgorithmParameterGenerator", "EC",
                "com.ibm.crypto.plus.provider.ECParameterGenerator", aliases));

        aliases = new String[] {"AESGCM"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameterGenerator", "GCM",
                "com.ibm.crypto.plus.provider.GCMParameterGenerator", aliases));

        aliases = new String[] {"AESCCM"};
        putService(new OpenJCEPlusService(jce, "AlgorithmParameterGenerator", "CCM",
                "com.ibm.crypto.plus.provider.CCMParameterGenerator", aliases));

        /* =======================================================================
         * Cipher engines
         * =======================================================================
         */
        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "AES/GCM/NoPadding",
                "com.ibm.crypto.plus.provider.AESGCMCipher", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "AES/CCM/NoPadding",
                "com.ibm.crypto.plus.provider.AESCCMCipher", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "AES",
                "com.ibm.crypto.plus.provider.AESCipher", aliases));

        aliases = new String[] {"AESWrap"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES/KW/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW", aliases));
        
        aliases = new String[] {"AESWrapPad"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES/KWP/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KWP", aliases));

        aliases = new String[] {"AESWrap_128",
                                "2.16.840.1.101.3.4.1.5",
                                "OID.2.16.840.1.101.3.4.1.5"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES_128/KW/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW_128", aliases));

        aliases = new String[] {"AESWrapPad_128",
                                "2.16.840.1.101.3.4.1.8",
                                "OID.2.16.840.1.101.3.4.1.8"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES_128/KWP/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KWP_128", aliases));
                
        aliases = new String[] {"AESWrap_192",
                                "2.16.840.1.101.3.4.1.25",
                                "OID.2.16.840.1.101.3.4.1.25"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES_192/KW/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW_192", aliases));
                
        aliases = new String[] {"AESWrapPad_192",
                                "2.16.840.1.101.3.4.1.28",
                                "OID.2.16.840.1.101.3.4.1.28"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES_192/KWP/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KWP_192", aliases));

        aliases = new String[] {"AESWrap_256",
                                "2.16.840.1.101.3.4.1.45",
                                "OID.2.16.840.1.101.3.4.1.45"};
        putService(new OpenJCEPlusService(jce, "Cipher", "AES_256/KW/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW_256", aliases));

        aliases = new String[] {"AESWrapPad_256",
                                "2.16.840.1.101.3.4.1.48",
                                "OID.2.16.840.1.101.3.4.1.48"};                
        putService(new OpenJCEPlusService(jce, "Cipher", "AES_256/KWP/NoPadding",
                "com.ibm.crypto.plus.provider.AESKeyWrapCipher$KWP_256", aliases));

        aliases = new String[] {"TripleDES", "3DES"};
        putService(new OpenJCEPlusService(jce, "Cipher", "DESede",
                "com.ibm.crypto.plus.provider.DESedeCipher", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "RSA", "com.ibm.crypto.plus.provider.RSA",
                aliases));
        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "ChaCha20",
                "com.ibm.crypto.plus.provider.ChaCha20Cipher", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "ChaCha20-Poly1305",
                "com.ibm.crypto.plus.provider.ChaCha20Poly1305Cipher", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA1AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA1AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA1AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA1AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA224AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA224AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA224AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA224AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA256AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA256AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA256AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA256AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA384AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA384AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA384AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA384AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA512AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA512AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA512AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA512AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA512/224AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA512_224AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA512/224AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA512_224AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA512/256AndAES_128",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA512_256AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Cipher", "PBEWithHmacSHA512/256AndAES_256",
                "com.ibm.crypto.plus.provider.PBES2Core$HmacSHA512_256AndAES_256", aliases));

        /* =======================================================================
         * Key agreement
         * =======================================================================
         */
        aliases = new String[] {"DH", "OID." + OID_PKCS3, OID_PKCS3};
        putService(new OpenJCEPlusService(jce, "KeyAgreement", "DiffieHellman",
                "com.ibm.crypto.plus.provider.DHKeyAgreement", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "KeyAgreement", "ECDH",
                "com.ibm.crypto.plus.provider.ECDHKeyAgreement", aliases));

        putService(new OpenJCEPlusService(jce, "KeyAgreement", "XDH",
                "com.ibm.crypto.plus.provider.XDHKeyAgreement$XDH", null));

        aliases = new String[] {"OID.1.3.101.110", "1.3.101.110"};
        putService(new OpenJCEPlusService(jce, "KeyAgreement", "X25519",
                "com.ibm.crypto.plus.provider.XDHKeyAgreement$X25519", aliases));

        aliases = new String[] {"OID.1.3.101.111", "1.3.101.111"};
        putService(new OpenJCEPlusService(jce, "KeyAgreement", "X448",
                "com.ibm.crypto.plus.provider.XDHKeyAgreement$X448", aliases));

        /* =======================================================================
         * Key factories
         * =======================================================================
         */
        aliases = new String[] {"DH", "OID." + OID_PKCS3, OID_PKCS3};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "DiffieHellman",
                "com.ibm.crypto.plus.provider.DHKeyFactory", aliases));

        aliases = new String[] {"OID.1.2.840.10040.4.1", "1.2.840.10040.4.1", "OID.1.3.14.3.2.12",
                "1.3.14.3.2.12", "DSAKeyFactory"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "DSA",
                "com.ibm.crypto.plus.provider.DSAKeyFactory", aliases));

        aliases = new String[] {"OID.1.2.840.10045.2.1", "1.2.840.10045.2.1", "EllipticCurve"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "EC",
                "com.ibm.crypto.plus.provider.ECKeyFactory", aliases));

        putService(new OpenJCEPlusService(jce, "KeyFactory", "XDH",
                "com.ibm.crypto.plus.provider.XDHKeyFactory$XDH", null));

        aliases = new String[] {"OID.1.3.101.110", "1.3.101.110"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "X25519",
                "com.ibm.crypto.plus.provider.XDHKeyFactory$X25519", aliases));

        aliases = new String[] {"OID.1.3.101.111", "1.3.101.111"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "X448",
                "com.ibm.crypto.plus.provider.XDHKeyFactory$X448", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "KeyFactory", "EdDSA",
                "com.ibm.crypto.plus.provider.EdDSAKeyFactory$EdDSA", aliases));

        aliases = new String[] {"OID.1.3.101.112", "1.3.101.112"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "Ed25519",
                "com.ibm.crypto.plus.provider.EdDSAKeyFactory$Ed25519", aliases));

        aliases = new String[] {"OID.1.3.101.113", "1.3.101.113"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "Ed448",
                "com.ibm.crypto.plus.provider.EdDSAKeyFactory$Ed448", aliases));

        aliases = new String[] {"OID.1.2.5.8.1.1", "1.2.5.8.1.1", "OID.1.2.840.113549.1.1.1",
                "1.2.840.113549.1.1.1", "OID.1.2.840.113549.1.1", "1.2.840.113549.1.1"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "RSA",
                "com.ibm.crypto.plus.provider.RSAKeyFactory$Legacy", aliases));

        aliases = new String[] {"RSA-PSS", "RSASSA-PSS", "RSASA-PSS", "OID.1.2.840.113549.1.1.10",
                "1.2.840.113549.1.1.10"};
        putService(new OpenJCEPlusService(jce, "KeyFactory", "RSAPSS",
                "com.ibm.crypto.plus.provider.RSAKeyFactory$PSS", aliases));

        /* =======================================================================
         * PQC key factories
         * =======================================================================
         */
        aliases = new String[] {"ML_KEM_512", "MLKEM512", "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1"};

        putService(new OpenJCEPlusService(jce, "KeyFactory", "ML-KEM-512",
                  "com.ibm.crypto.plus.provider.PQCKeyFactory$MLKEM512", aliases));

        aliases = new String[] {"ML-KEM", "ML_KEM_768", "MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2"};

        putService(new OpenJCEPlusService(jce, "KeyFactory", "ML-KEM-768",
               "com.ibm.crypto.plus.provider.PQCKeyFactory$MLKEM768", aliases));
                
        aliases = new String[] {"ML_KEM_1024", "MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3"};

        putService(new OpenJCEPlusService(jce, "KeyFactory", "ML-KEM-1024",
               "com.ibm.crypto.plus.provider.PQCKeyFactory$MLKEM1024", aliases));
                        
        aliases = new String[] {"ML_DSA_44", "MLDSA44", "OID.2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17"};

        putService(new OpenJCEPlusService(jce, "KeyFactory", "ML-DSA-44",
               "com.ibm.crypto.plus.provider.PQCKeyFactory$MLDSA44", aliases));
                               
        aliases = new String[] {"ML-DSA", "ML_DSA_65", "MLDSA65", "OID.2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18"};

        putService(new OpenJCEPlusService(jce, "KeyFactory", "ML-DSA-65",
               "com.ibm.crypto.plus.provider.PQCKeyFactory$MLDSA65", aliases));
                                
        aliases = new String[] {"ML_DSA_87", "MLDSA87", "OID.2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19"};

        putService(new OpenJCEPlusService(jce, "KeyFactory", "ML-DSA-87",
               "com.ibm.crypto.plus.provider.PQCKeyFactory$MLDSA87", aliases));
        
        /* =======================================================================
         * Key Generator engines
         * =======================================================================
         */
        aliases = new String[] {"2.16.840.1.101.3.4.1", "OID.2.16.840.1.101.3.4.1"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "AES",
                "com.ibm.crypto.plus.provider.AESKeyGenerator", aliases));

        aliases = new String[] {"TripleDES", "3DES"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "DESede",
                "com.ibm.crypto.plus.provider.DESedeKeyGenerator", aliases));

        aliases = new String[] {"HMACwithMD5"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacMD5",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacMD5", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.7", "1.2.840.113549.2.7", "HMACwithSHA1",
                "HMACwithSHA-1", "HmacSHA-1"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA1",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA1", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.8", "1.2.840.113549.2.8", "HMACwithSHA224",
                "HMACwithSHA-224", "HmacSHA-224"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA224",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA224", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.9", "1.2.840.113549.2.9", "HMACwithSHA256",
                "HMACwithSHA-256", "HmacSHA-256"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA256",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA256", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.10", "1.2.840.113549.2.10", "HMACwithSHA384",
                "HMACwithSHA-384", "HmacSHA-384"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA384",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA384", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.11", "1.2.840.113549.2.11", "HMACwithSHA512",
                "HMACwithSHA-512", "HmacSHA-512"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA512",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA512", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.13", "2.16.840.1.101.3.4.2.13",
                "HMACwithSHA3-224", "HmacSHA3-224"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA3-224",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA3_224", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.14", "2.16.840.1.101.3.4.2.14",
                "HMACwithSHA3-256", "HmacSHA3-256"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA3-256",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA3_256", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.15", "2.16.840.1.101.3.4.2.15",
                "HMACwithSHA3-384", "HmacSHA3-384"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA3-384",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA3_384", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.16", "2.16.840.1.101.3.4.2.16",
                "HMACwithSHA3-512", "HmacSHA3-512"};
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "HmacSHA3-512",
                "com.ibm.crypto.plus.provider.HmacKeyGenerator$HmacSHA3_512", aliases));

        // Used for both ChaCha20 and ChaCha20-Poly1305 ciphers
        aliases = null;
        putService(new OpenJCEPlusService(jce, "KeyGenerator", "ChaCha20",
                "com.ibm.crypto.plus.provider.ChaCha20KeyGenerator", aliases));

        /* =======================================================================
         * Keypair Generator engines
         * =======================================================================
         */
        aliases = new String[] {"DH", "OID." + OID_PKCS3, OID_PKCS3};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "DiffieHellman",
                "com.ibm.crypto.plus.provider.DHKeyPairGenerator", aliases));

        aliases = new String[] {"OID.1.2.840.10040.4.1", "1.2.840.10040.4.1", "OID.1.3.14.3.2.12",
                "1.3.14.3.2.12"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "DSA",
                "com.ibm.crypto.plus.provider.DSAKeyPairGenerator", aliases));

        aliases = new String[] {"OID.1.2.840.10045.2.1", "1.2.840.10045.2.1", "EllipticCurve"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "EC",
                "com.ibm.crypto.plus.provider.ECKeyPairGenerator", aliases));

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "XDH",
                "com.ibm.crypto.plus.provider.XDHKeyPairGenerator$XDH", null));

        aliases = new String[] {"OID.1.3.101.110", "1.3.101.110"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "X25519",
                "com.ibm.crypto.plus.provider.XDHKeyPairGenerator$X25519", aliases));

        aliases = new String[] {"OID.1.3.101.111", "1.3.101.111"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "X448",
                "com.ibm.crypto.plus.provider.XDHKeyPairGenerator$X448", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "EdDSA",
                "com.ibm.crypto.plus.provider.EdDSAKeyPairGenerator$EdDSA", aliases));

        aliases = new String[] {"1.3.101.112", "OID.1.3.101.112"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "Ed25519",
                "com.ibm.crypto.plus.provider.EdDSAKeyPairGenerator$Ed25519", aliases));

        aliases = new String[] {"1.3.101.113", "OID.1.3.101.113"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "Ed448",
                "com.ibm.crypto.plus.provider.EdDSAKeyPairGenerator$Ed448", aliases));

        aliases = new String[] {"OID.1.2.5.8.1.1", "1.2.5.8.1.1", "OID.1.2.840.113549.1.1",
                "1.2.840.113549.1.1"};
        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "RSA",
                "com.ibm.crypto.plus.provider.RSAKeyPairGenerator$Legacy", aliases));

        aliases = new String[] {"RSA-PSS", "RSASSA-PSS", "RSASA-PSS"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "RSAPSS",
                "com.ibm.crypto.plus.provider.RSAKeyPairGenerator$PSS", aliases));

        /* =======================================================================
         * PQC key pair generators
         * =======================================================================
         */
        aliases = null;

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-KEM",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLKEM", aliases));

        aliases = null;

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-DSA",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLDSA", aliases));

        aliases = new String[] {"ML_KEM_512", "MLKEM512", "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-KEM-512",
                  "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLKEM512", aliases));

        aliases = new String[] {"ML_KEM_768", "MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-KEM-768",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLKEM768", aliases));

        aliases = new String[] {"ML_KEM_1024", "MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-KEM-1024",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLKEM1024", aliases));

        aliases = new String[] {"ML_DSA_44", "MLDSA44", "OID.2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-DSA-44",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLDSA44", aliases));

        aliases = new String[] {"ML_DSA_65", "MLDSA65", "OID.2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-DSA-65",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLDSA65", aliases));

        aliases = new String[] {"ML_DSA_87", "MLDSA87", "OID.2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19"};

        putService(new OpenJCEPlusService(jce, "KeyPairGenerator", "ML-DSA-87",
               "com.ibm.crypto.plus.provider.PQCKeyPairGenerator$MLDSA87", aliases)); 

        /* =======================================================================
         * Message authentication engines
         * =======================================================================
         */

        aliases = new String[] {"HMACwithMD5"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacMD5",
                "com.ibm.crypto.plus.provider.HmacCore$HmacMD5", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.7", "1.2.840.113549.2.7", "HMACwithSHA1",
                "HMACwithSHA-1", "HmacSHA-1"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA1",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA1", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.8", "1.2.840.113549.2.8", "HMACwithSHA224",
                "HMACwithSHA-224", "HmacSHA-224"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA224",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA224", aliases));

        aliases = new String[] {

                "OID.1.2.840.113549.2.9", "1.2.840.113549.2.9", "HMACwithSHA256", // Added per tag [IBM-ALIASES]/ in DesignNotes.txt
                "HMACwithSHA-256", "HmacSHA-256"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA256",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA256", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.10", "1.2.840.113549.2.10", "HMACwithSHA384", // Added per tag [IBM-ALIASES]    in DesignNotes.txt
                "HMACwithSHA-384", "HmacSHA-384"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA384",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA384", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.11", "1.2.840.113549.2.11", "HMACwithSHA512",
                "HMACwithSHA-512", "HmacSHA-512"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA512",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA512", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.13", "2.16.840.1.101.3.4.2.13",
                "HMACwithSHA3-224", "HmacSHA3-224"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-224",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_224", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.14", "2.16.840.1.101.3.4.2.14",
                "HMACwithSHA3-256", "HmacSHA3-256"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-256",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_256", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.15", "2.16.840.1.101.3.4.2.15",
                "HMACwithSHA3-384", "HmacSHA3-384"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-384",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_384", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.16", "2.16.840.1.101.3.4.2.16",
                "HMACwithSHA3-512", "HmacSHA3-512"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-512",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_512", aliases));

        if (allowLegacyHKDF) {
            /* =======================================================================
             * HKDF Algorithms use KeyGeneratorSpi - Legacy way of using
             * =======================================================================
             */
            aliases = new String[] {"kda-hkdf-with-sha-1"};
            putService(new OpenJCEPlusService(jce, "KeyGenerator", "kda-hkdf-with-sha1",
                    "com.ibm.crypto.plus.provider.HKDFGenerator$HKDFwithSHA1", aliases));

            aliases = new String[] {"kda-hkdf-with-sha-224"};
            putService(new OpenJCEPlusService(jce, "KeyGenerator", "kda-hkdf-with-sha224",
                    "com.ibm.crypto.plus.provider.HKDFGenerator$HKDFwithSHA224", aliases));

            aliases = new String[] {"kda-hkdf-with-sha-256"};
            putService(new OpenJCEPlusService(jce, "KeyGenerator", "kda-hkdf-with-sha256",
                    "com.ibm.crypto.plus.provider.HKDFGenerator$HKDFwithSHA256", aliases));
            aliases = new String[] {"kda-hkdf-with-sha-384"};
            putService(new OpenJCEPlusService(jce, "KeyGenerator", "kda-hkdf-with-sha384",
                    "com.ibm.crypto.plus.provider.HKDFGenerator$HKDFwithSHA384", aliases));
            aliases = new String[] {"kda-hkdf-with-sha-512"};
            putService(new OpenJCEPlusService(jce, "KeyGenerator", "kda-hkdf-with-sha512",
                    "com.ibm.crypto.plus.provider.HKDFGenerator$HKDFwithSHA512", aliases));
        }

        /* =======================================================================
         * Key Derivation engines
         * =======================================================================
         */
        putService(new OpenJCEPlusService(jce, "KDF", "HKDF-SHA256",
                "com.ibm.crypto.plus.provider.HKDFKeyDerivation$HKDFSHA256", null));
        putService(new OpenJCEPlusService(jce, "KDF", "HKDF-SHA384",
                "com.ibm.crypto.plus.provider.HKDFKeyDerivation$HKDFSHA384", null));
        putService(new OpenJCEPlusService(jce, "KDF", "HKDF-SHA512",
                "com.ibm.crypto.plus.provider.HKDFKeyDerivation$HKDFSHA512", null));

        /* =======================================================================
         * MessageDigest engines
         * =======================================================================
         */
        aliases = null;
        putService(new OpenJCEPlusService(jce, "MessageDigest", "MD5",
                "com.ibm.crypto.plus.provider.MessageDigest$MD5", aliases));

        aliases = new String[] {"SHA", "SHA1", "OID.1.3.14.3.2.26", "1.3.14.3.2.26"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-1",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA1", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.4", "SHA224"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-224",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA224", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.1", "SHA2",
                "SHA-2", "SHA256"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-256",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA256", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.2", "SHA3",
                "SHA-3", "SHA384"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-384",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA384", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.3", "2.16.840.1.101.3.4.2.3", "SHA5",
                "SHA-5", "SHA512"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-512",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA512", aliases));

        // SHA512-224
        aliases = new String[] {"SHA512/224", "OID.2.16.840.1.101.3.4.2.5",
                "2.16.840.1.101.3.4.2.5", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-512/224",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA512_224", aliases));

        // SHA512-256
        aliases = new String[] {"SHA512/256", "OID.2.16.840.1.101.3.4.2.6",
                "2.16.840.1.101.3.4.2.6", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-512/256",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA512_256", aliases));

        //SHA3 Hashes

        aliases = new String[] {"SHA3-224", "OID.2.16.840.1.101.3.4.2.7",
                "2.16.840.1.101.3.4.2.7", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-224",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_224", aliases));
        aliases = new String[] {"SHA3-256", "OID.2.16.840.1.101.3.4.2.8",
                "2.16.840.1.101.3.4.2.8", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-256",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_256", aliases));
        aliases = new String[] {"SHA3-384", "OID.2.16.840.1.101.3.4.2.9",
                "2.16.840.1.101.3.4.2.9", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-384",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_384", aliases));
        aliases = new String[] {"SHA3-512", "OID.2.16.840.1.101.3.4.2.10",
                "2.16.840.1.101.3.4.2.10", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-512",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_512", aliases));

        /* =======================================================================
         * PQC key encapsulation mechanisms
         * =======================================================================
         */
        aliases = new String[] {"ML_KEM_512", "MLKEM512", "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1"};

        putService(new OpenJCEPlusService(jce, "KEM", "ML-KEM-512",
               "com.ibm.crypto.plus.provider.MLKEMImpl$MLKEM512", aliases));

        aliases = new String[] {"ML-KEM", "ML_KEM_768", "MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2"};

        putService(new OpenJCEPlusService(jce, "KEM", "ML-KEM-768",
               "com.ibm.crypto.plus.provider.MLKEMImpl$MLKEM768", aliases));

        aliases = new String[] {"ML_KEM_1024", "MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3"};

        putService(new OpenJCEPlusService(jce, "KEM", "ML-KEM-1024",
               "com.ibm.crypto.plus.provider.MLKEMImpl$MLKEM1024", aliases));

        /* =======================================================================
         * Secret key factories
         * =======================================================================
         */
        aliases = new String[] {"2.16.840.1.101.3.4.1", "OID.2.16.840.1.101.3.4.1"};
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "AES",
                "com.ibm.crypto.plus.provider.AESKeyFactory", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA1",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA1",
                                     aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA224",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA224",
                                     aliases));
                                     
        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA256",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA256",
                                     aliases));
        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA384",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA384",
                                     aliases));
        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA512",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA512",
                                     aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA512/224",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA512_224",
                                     aliases));
        
        aliases = null;
        putService(new OpenJCEPlusService(jce,
                                     "SecretKeyFactory",
                                     "PBKDF2WithHmacSHA512/256",
                                     "com.ibm.crypto.plus.provider.PBKDF2Core$HmacSHA512_256",
                                     aliases));

        aliases = new String[] {"TripleDES", "3DES"};
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "DESede",
                "com.ibm.crypto.plus.provider.DESedeKeyFactory", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "ChaCha20",
                "com.ibm.crypto.plus.provider.ChaCha20KeyFactory", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA1AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA1AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA1AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA1AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA224AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA224AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA224AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA224AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA256AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA256AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA256AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA256AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA384AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA384AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA384AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA384AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA512AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA512AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA512AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA512AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA512/224AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA512_224AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA512/224AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA512_224AndAES_256", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA512/256AndAES_128",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA512_256AndAES_128", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "SecretKeyFactory", "PBEWithHmacSHA512/256AndAES_256",
                "com.ibm.crypto.plus.provider.PBEKeyFactory$PBEWithHmacSHA512_256AndAES_256", aliases));
        
        /* =======================================================================
         * SecureRandom
         * =======================================================================
         */
        Map<String, String> attrsSecureRandom = new HashMap<>();
        attrsSecureRandom.put("ThreadSafe", "true");
        aliases = new String[] {"HASHDRBG", "SHA2DRBG"};
        putService(new OpenJCEPlusService(jce, "SecureRandom", "SHA256DRBG",
                "com.ibm.crypto.plus.provider.HASHDRBG$SHA256DRBG", aliases, attrsSecureRandom));

        aliases = new String[] {"SHA5DRBG"};
        putService(new OpenJCEPlusService(jce, "SecureRandom", "SHA512DRBG",
                "com.ibm.crypto.plus.provider.HASHDRBG$SHA512DRBG", aliases, attrsSecureRandom));

        /* =======================================================================
         * Signature engines
         * =======================================================================
         */
        aliases = new String[] {"DSAforSSL"};
        putService(new OpenJCEPlusService(jce, "Signature", "NONEwithDSA",
                "com.ibm.crypto.plus.provider.DSASignatureNONE", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Signature", "NONEwithRSA",
                "com.ibm.crypto.plus.provider.RSASignatureNONE", aliases));

        aliases = null;
        putService(new OpenJCEPlusService(jce, "Signature", "RSAforSSL",
                "com.ibm.crypto.plus.provider.RSASignatureSSL", aliases));

        aliases = new String[] {"ECDSAforSSL"};

        putService(new OpenJCEPlusService(jce, "Signature", "NONEwithECDSA",
                "com.ibm.crypto.plus.provider.DatawithECDSA", aliases));

        aliases = new String[] {"DSA", "OID.1.2.840.10040.4.3", "1.2.840.10040.4.3",
                "OID.1.3.14.3.2.13", "1.3.14.3.2.13", "OID.1.3.14.3.2.27", "1.3.14.3.2.27",
                "SHA-1withDSA", "SHA-1/DSA", "SHA1/DSA", "SHA/DSA", "DSS", "SHAwithDSA",
                "DSAWithSHA1"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA1withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA1withDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.1", "2.16.840.1.101.3.4.3.1",
                "SHA-224withDSA", "SHA224/DSA", "SHA-224/DSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA224withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA224withDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.2", "2.16.840.1.101.3.4.3.2",
                "SHA2withDSA", // Added per tag IBM-ALIASES] in DesignNotes.txt
                "SHA-2withDSA", "SHA-256withDSA", "SHA2/DSA", "SHA-2/DSA", "SHA-256/DSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA256withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA256withDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.5", "2.16.840.1.101.3.4.3.5",
                "SHA3-224withDSA", "SHA3-224/DSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-224withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA3_224withDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.6", "2.16.840.1.101.3.4.3.6",
                "SHA3-256withDSA", // Added per tag IBM-ALIASES] in DesignNotes.txt
                "SHA3-256/DSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-256withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA3_256withDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.7", "2.16.840.1.101.3.4.3.7",
                "SHA3-384withDSA", "SHA3-384/DSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-384withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA3_384withDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.8", "2.16.840.1.101.3.4.3.8",
                "SHA3-512withDSA", // Added per tag IBM-ALIASES] in DesignNotes.txt
                "SHA3-512/DSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-512withDSA",
                "com.ibm.crypto.plus.provider.DSASignature$SHA3_512withDSA", aliases));

        aliases = new String[] {"OID.1.2.840.10045.4.1", "1.2.840.10045.4.1", "SHAwithECDSA",
                "SHA-1withECDSA", "SHA/ECDSA", "SHA-1/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA1withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA1withECDSA", aliases));

        aliases = new String[] {"OID.1.2.840.10045.4.3.1", "1.2.840.10045.4.3.1", "SHA224/ECDSA",
                "SHA-224/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA224withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA224withECDSA", aliases));

        aliases = new String[] {"OID.1.2.840.10045.4.3.2", "1.2.840.10045.4.3.2", "SHA2withECDSA",
                "SHA2/ECDSA", "SHA-256/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA256withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA256withECDSA", aliases));

        aliases = new String[] {"OID.1.2.840.10045.4.3.3", "1.2.840.10045.4.3.3", "SHA3withECDSA",
                "SHA3/ECDSA", "SHA-384/ECDSA"// Added per tag [IBM-ALIASES] in DesignNotes.txt
        };
        putService(new OpenJCEPlusService(jce, "Signature", "SHA384withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA384withECDSA", aliases));

        aliases = new String[] {"OID.1.2.840.10045.4.3.4", "1.2.840.10045.4.3.4", "SHA5withECDSA",
                "SHA5/ECDSA", "SHA-512/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA512withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA512withECDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.9", "2.16.840.1.101.3.4.3.9",
                "SHA3-224withECDSA", "SHA3-224/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-224withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA3_224withECDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.10", "2.16.840.1.101.3.4.3.10",
                "SHA3-256withECDSA", "SHA3-256/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-256withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA3_256withECDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.11", "2.16.840.1.101.3.4.3.11",
                "SHA3-384withECDSA", "SHA3-384/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-384withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA3_384withECDSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.12", "2.16.840.1.101.3.4.3.12",
                "SHA3-512withECDSA", "SHA3-512/ECDSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-512withECDSA",
                "com.ibm.crypto.plus.provider.ECDSASignature$SHA3_512withECDSA", aliases));

        aliases = new String[] {"OID.1.2.840.113549.1.1.5", "1.2.840.113549.1.1.5",
                "OID.1.3.14.3.2.29", "1.3.14.3.2.29", "OID.1.3.14.3.2.26", "1.3.14.3.2.26",
                "SHA-1withRSA", "SHAwithRSA", "SHA-1/RSA", "SHA1/RSA", "SHA/RSA", "RSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA1withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA1withRSA", aliases));

        aliases = new String[] {"OID.1.2.840.113549.1.1.14", "1.2.840.113549.1.1.14", "SHA-224/RSA",
                "SHA224/RSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA224withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA224withRSA", aliases));

        aliases = new String[] {"OID.1.2.840.113549.1.1.11", "1.2.840.113549.1.1.11", "SHA-256/RSA",
                "SHA2withRSA", "SHA2/RSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA256withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA256withRSA", aliases));

        aliases = new String[] {"OID.1.2.840.113549.1.1.12", "1.2.840.113549.1.1.12", "SHA-384/RSA",
                "SHA3withRSA", "SHA3/RSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA384withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA384withRSA", aliases));

        aliases = new String[] {"OID.1.2.840.113549.1.1.13", "1.2.840.113549.1.1.13", "SHA-512/RSA",
                "SHA5withRSA", "SHA5/RSA"};
        putService(new OpenJCEPlusService(jce, "Signature", "SHA512withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA512withRSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.13", "2.16.840.1.101.3.4.3.13",
                "SHA3-224/RSA", "SHA3-224withRSA", };
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-224withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA3_224withRSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.14", "2.16.840.1.101.3.4.3.14",
                "SHA3-256/RSA", "SHA3-256withRSA", };
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-256withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA3_256withRSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.15", "2.16.840.1.101.3.4.3.15",
                "SHA3-384/RSA", "SHA3-384withRSA", };
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-384withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA3_384withRSA", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.3.16", "2.16.840.1.101.3.4.3.16",
                "SHA3-512/RSA", "SHA3-512withRSA", };
        putService(new OpenJCEPlusService(jce, "Signature", "SHA3-512withRSA",
                "com.ibm.crypto.plus.provider.RSASignature$SHA3_512withRSA", aliases));

        aliases = new String[] {"RSA-PSS", "RSASSA-PSS", "RSASA-PSS", "OID.1.2.840.113549.1.1.10",
                "1.2.840.113549.1.1.10"};
        putService(new OpenJCEPlusService(jce, "Signature", "RSAPSS",
                "com.ibm.crypto.plus.provider.RSAPSSSignature", aliases));
        aliases = null;
        putService(new OpenJCEPlusService(jce, "Signature", "EdDSA",
                "com.ibm.crypto.plus.provider.EdDSASignature$EdDSA", aliases));

        aliases = new String[] {"OID.1.3.101.112", "1.3.101.112"};
        putService(new OpenJCEPlusService(jce, "Signature", "Ed25519",
                "com.ibm.crypto.plus.provider.EdDSASignature$Ed25519", aliases));

        aliases = new String[] {"OID.1.3.101.113", "1.3.101.113"};
        putService(new OpenJCEPlusService(jce, "Signature", "Ed448",
                "com.ibm.crypto.plus.provider.EdDSASignature$Ed448", aliases));

        /* =======================================================================
         * PQC signatures
         * =======================================================================
         */
        aliases = new String[] {"ML_DSA_44", "MLDSA44", "OID.2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17"};

        putService(new OpenJCEPlusService(jce, "Signature", "ML-DSA-44",
               "com.ibm.crypto.plus.provider.PQCSignatureImpl$MLDSA44", aliases));

        aliases = new String[] {"ML-DSA", "ML_DSA_65", "MLDSA65", "OID.2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18"};

        putService(new OpenJCEPlusService(jce, "Signature", "ML-DSA-65",
               "com.ibm.crypto.plus.provider.PQCSignatureImpl$MLDSA65", aliases));

        aliases = new String[] {"ML_DSA_87", "MLDSA87", "OID.2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19"};

        putService(new OpenJCEPlusService(jce, "Signature", "ML-DSA-87",
               "com.ibm.crypto.plus.provider.PQCSignatureImpl$MLDSA87", aliases));
    }

    // Return the instance of this class or create one if needed.
    //
    static OpenJCEPlus getInstance() {
        if (instance == null) {
            return new OpenJCEPlus();
        }
        return instance;
    }

    private static class OpenJCEPlusContext extends ProviderContext {

        private static final long serialVersionUID = -1409417302968036811L;

        OpenJCEPlusContext() {}

        OpenJCEPlusProvider getProvider() {
            return OpenJCEPlus.getInstance();
        }
    }

    ProviderContext getProviderContext() {
        return new OpenJCEPlusContext();
    }

    // Get SecureRandom to use for crypto operations.
    //
    java.security.SecureRandom getSecureRandom(java.security.SecureRandom userSecureRandom) {
        try {
            return java.security.SecureRandom.getInstance("SHA256DRBG", this);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException("SecureRandom not available");
        }
    }

    // Initialize OCK context(s)
    //
    private synchronized void initializeContext() {
        // Leave this duplicate check in here. If two threads are both trying
        // to instantiate an OpenJCEPlus provider at the same time, we need to
        // ensure that the initialization only happens one time. We have
        // made the method synchronizaed to ensure only one thread can execute
        // the method at a time.
        //
        if (ockInitialized) {
            return;
        }

        try {
            boolean useFIPSMode = false;

            ockContext = OCKContext.createContext(useFIPSMode);
            ockInitialized = true;
        } catch (OCKException e) {
            throw providerException("Failed to initialize OpenJCEPlus provider", e);
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlus provider", t);

            if (exceptionToThrow.getCause() == null) {
                // We are not including the full stack trace back to the point
                // of origin.
                // Try and obtain the message for the underlying cause of the
                // exception
                //
                // If an ExceptionInInitializerError or NoClassDefFoundError is
                // thrown, we want to get the message from the cause of that
                // exception.
                //
                if ((t instanceof java.lang.ExceptionInInitializerError)
                        || (t instanceof java.lang.NoClassDefFoundError)) {
                    Throwable cause = t.getCause();
                    if (cause != null) {
                        t = cause;
                    }
                }

                // In the case that the JNI library could not be loaded.
                //
                String message = t.getMessage();
                if ((message != null) && (message.length() > 0)) {
                    // We want to see the message for the underlying cause even
                    // if not showing the stack trace all the way back to the
                    // point of origin.
                    //
                    exceptionToThrow.initCause(new ProviderException(t.getMessage()));
                }
            }

            if (debug != null) {
                exceptionToThrow.printStackTrace(System.out);
            }

            throw exceptionToThrow;
        }
    }

    // Get OCK context for crypto operations
    //
    OCKContext getOCKContext() {
        // May need to initialize OCK here in the case that a serialized
        // OpenJCEPlus object, such as a HASHDRBG SecureRandom, is being
        // deserialized in a JVM that has not instantiated the OpenJCEPlus
        // provider yet.
        //
        if (!ockInitialized) {
            initializeContext();
        }

        return ockContext;
    }

    ProviderException providerException(String message, Throwable ockException) {
        ProviderException providerException = new ProviderException(message, ockException);
        setOCKExceptionCause(providerException, ockException);
        return providerException;
    }

    // Get the date from the ImplementationVersion in the manifest file
    private static String getDebugDate(String className) {
        String versionDate = "Unknown";
        try {
            Class<?> thisClass = Class.forName(className);
            Package thisPackage = thisClass.getPackage();
            String versionInfo = thisPackage.getImplementationVersion();
            int index = versionInfo.indexOf("_");
            versionDate = (index == -1) ? versionInfo : versionInfo.substring(index + 1);
        } catch (Exception e) {
            // IGNORE EXCEPTION
        }
        return versionDate;
    }
}
