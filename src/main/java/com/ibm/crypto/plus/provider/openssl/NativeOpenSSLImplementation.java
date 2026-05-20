/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeImplementation;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;
import sun.security.util.Debug;

final class NativeOpenSSLImplementation extends NativeImplementation {

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    // Whether OpenSSL is dynamically loaded. If OpenSSL is dynamically loaded,
    // we want to pre-load OpenSSL to help ensure we are getting the expected
    // version.
    //
    private static final boolean osslDynamicallyLoaded = true;

    // If OpenSSL is dynamically loaded, whether to require that OpenSSL be
    // pre-loaded.
    //
    static boolean requirePreloadOSSL = true;

    // Default library names
    //
    private static final String OPENSSL_CORE_LIBRARY_NAME = "crypto";
    private static final String OPENJCEPLUS_CORE_LIBRARY_NAME = "openjceplus";
    private static String osName = null;
    private static String osArch = null;
    private static String JVMFIPSmode = null;

    static {
        if (osslDynamicallyLoaded) {
            // Preload OpenSSL library. We want to pre-load OpenSSL to help
            // ensure we are picking up the expected version within
            // the JRE.
            //
            preloadOpenSSL();
        }
        // Load native code for java-gskit
        //
        preloadOpenJCEPlusNative();
    }

    public static String getOsName() {
        return osName;
    }

    public static String getOsArch() {
        return osArch;

    }

    static File getOSSLLoadFile() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");

        File loadFile = null;

        String osslPath = System.getProperty("openssl.library.path");
        if (osslPath != null) {
            if (debug != null) {
                debug.println("Loading openssl library using value in property openssl.library.path: "
                    + osslPath);
            }

            if (osName.equals("Mac OS X")) {
                loadFile = new File(osslPath, "lib" + OPENSSL_CORE_LIBRARY_NAME + ".dylib");
            } else if (osName.startsWith("Windows") && osArch.equals("amd64")) {
                loadFile = new File(osslPath, OPENSSL_CORE_LIBRARY_NAME + ".dll");
            } else {
                loadFile = new File(osslPath, "lib" + OPENSSL_CORE_LIBRARY_NAME + ".so");
            }
            return loadFile;
        }
        if (debug != null) {
            debug.println("Library path not found for openssl, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");

        if (osName.startsWith("Windows")) {
            osslPath = javaHome + File.separator + "bin";
        } else {
            osslPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading openssl library using value: " + osslPath);
        }

        if (osName.equals("Mac OS X")) {
            loadFile = new File(osslPath, "lib" + OPENSSL_CORE_LIBRARY_NAME + "-semeru.dylib");
        } else if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(osslPath, OPENSSL_CORE_LIBRARY_NAME + "-semeru.dll");
        } else {
            loadFile = new File(osslPath, "lib" + OPENSSL_CORE_LIBRARY_NAME + "-semeru.so");
        }
        return loadFile;
    }

    static String getOpenJCEPlusNativeLoadPath() {
        String ojpOverridePath = System.getProperty("openjceplus.library.path");
        if (ojpOverridePath != null) {
            if (debug != null) {
                debug.println("Loading openjceplus native library using value in property openjceplus.library.path: " + ojpOverridePath);
            }
            return ojpOverridePath;
        }
        if (debug != null) {
            debug.println("Libpath not found for openjceplus native library, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String ojpPath;

        if (osName.startsWith("Windows")) {
            ojpPath = javaHome + File.separator + "bin";
        } else {
            ojpPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading openjceplus native library using value: " + ojpPath);
        }
        return ojpPath;
    }

    static void preloadOpenJCEPlusNative() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String ojpPath = getOpenJCEPlusNativeLoadPath();
        File loadFile = null;
        if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(ojpPath, "lib" + OPENJCEPLUS_CORE_LIBRARY_NAME + "_64.dll");
        } else if (osName.equals("Mac OS X")) {
            loadFile = new File(ojpPath, "lib" + OPENJCEPLUS_CORE_LIBRARY_NAME + ".dylib");
        } else {
            loadFile = new File(ojpPath, "lib" + OPENJCEPLUS_CORE_LIBRARY_NAME + ".so");
        }

        boolean ojpLibraryPreloaded = loadIfExists(loadFile);
        if (ojpLibraryPreloaded == false) {
            throw new ProviderException("Could not load dependent " + OPENJCEPLUS_CORE_LIBRARY_NAME + " library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    static void preloadOpenSSL() {
        
        File loadFile = getOSSLLoadFile();
        boolean osslLibraryPreloaded = loadIfExists(loadFile);
        if ((osslLibraryPreloaded == false) && requirePreloadOSSL) {
            throw new ProviderException("Could not load dependent openssl library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    

    // =========================================================================
    // General functions
    // =========================================================================

    static public native String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    static public native long initializeOSSL(boolean isFIPS) throws OpenSSLException;

    static public native String CTX_getValue(long osslContextId, int valueId) throws OpenSSLException;

    static native long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    static public native void RAND_nextBytes(long osslContextId, byte[] buffer) throws OpenSSLException;

    static public native void RAND_setSeed(long osslContextId, byte[] seed) throws OpenSSLException;

    static public native void RAND_generateSeed(long osslContextId, byte[] seed) throws OpenSSLException;

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    static public native long EXTRAND_create(long osslContextId, String algName) throws OpenSSLException;

    static public native void EXTRAND_nextBytes(long osslContextId, long PRNGContextId,
            byte[] buffer) throws OpenSSLException;

    static public native void EXTRAND_setSeed(long osslContextId, long PRNGContextId, byte[] seed)
            throws OpenSSLException;

    static public native void EXTRAND_delete(long osslContextId, long PRNGContextId)
            throws OpenSSLException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    static public native long CIPHER_create(long osslContextId, String cipher) throws OpenSSLException;

    static public native void CIPHER_init(long osslContextId, long cipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv) throws OpenSSLException;

    static public native void CIPHER_clean(long osslContextId, long cipherId) throws OpenSSLException;

    static public native void CIPHER_setPadding(long osslContextId, long cipherId, int paddingId)
            throws OpenSSLException;

    static public native int CIPHER_getBlockSize(long osslContextId, long cipherId);

    static public native int CIPHER_getKeyLength(long osslContextId, long cipherId);

    static public native int CIPHER_getIVLength(long osslContextId, long cipherId);

    static public native int CIPHER_getOID(long osslContextId, long cipherId);

    static public native int CIPHER_encryptUpdate(long osslContextId, long cipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OpenSSLException;

    static public native int CIPHER_decryptUpdate(long osslContextId, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws OpenSSLException;

    static public native int CIPHER_encryptFinal(long osslContextId, long cipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit)
            throws OpenSSLException;

    static public native int CIPHER_decryptFinal(long osslContextId, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws OpenSSLException;

    static public native long checkHardwareSupport(long osslContextId);

    static public native void CIPHER_delete(long osslContextId, long cipherId)
            throws OpenSSLException;

    static public native byte[] CIPHER_KeyWraporUnwrap(long osslContextId, byte[] key, byte[] KEK, int type)
            throws OpenSSLException;

    static public native int z_kmc_native(byte[] input, int inputOffset, byte[] output,
            int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    static public native long POLY1305CIPHER_create(long osslContextId, String cipher)
            throws OpenSSLException;

    static public native void POLY1305CIPHER_init(long osslContextId, long cipherId,
            int isEncrypt, byte[] key, byte[] iv) throws OpenSSLException;

    static public native void POLY1305CIPHER_clean(long osslContextId, long cipherId)
            throws OpenSSLException;

    static public native void POLY1305CIPHER_setPadding(long osslContextId, long cipherId,
            int paddingId) throws OpenSSLException;

    static public native int POLY1305CIPHER_getBlockSize(long osslContextId, long cipherId);

    static public native int POLY1305CIPHER_getKeyLength(long osslContextId, long cipherId);

    static public native int POLY1305CIPHER_getIVLength(long osslContextId, long cipherId);

    static public native int POLY1305CIPHER_getOID(long osslContextId, long cipherId);

    static public native int POLY1305CIPHER_encryptUpdate(long osslContextId, long cipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset) throws OpenSSLException;

    static public native int POLY1305CIPHER_decryptUpdate(long osslContextId, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws OpenSSLException;

    static public native int POLY1305CIPHER_encryptFinal(long osslContextId, long cipherId,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset,
            byte[] tag) throws OpenSSLException;

    static public native int POLY1305CIPHER_decryptFinal(long osslContextId, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, byte[] tag) throws OpenSSLException;

    static public native void POLY1305CIPHER_delete(long osslContextId, long cipherId)
            throws OpenSSLException;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    static public native long do_GCM_checkHardwareGCMSupport(long osslContextId);

    static public native int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OpenSSLException;

    static public native int do_GCM_encryptFastJNI(long osslContextId, long gcmCtx, int keyLen,
            int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException;

    static public native int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OpenSSLException;

    static public native int do_GCM_decryptFastJNI(long osslContextId, long gcmCtx, int keyLen,
            int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OpenSSLException;

    static public native int do_GCM_encrypt(long osslContextId, long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OpenSSLException;

    static public native int do_GCM_decrypt(long osslContextId, long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException;

    static public native int do_GCM_FinalForUpdateEncrypt(long osslContextId, long gcmCtx,
            byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OpenSSLException;

    static public native int do_GCM_FinalForUpdateDecrypt(long osslContextId, long gcmCtx,
            /* byte[] key, int keyLen,
             byte[] iv, int ivLen,*/
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException;

    static public native int do_GCM_UpdForUpdateEncrypt(long osslContextId, long gcmCtx,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset)
            throws OpenSSLException;

    static public native int do_GCM_UpdForUpdateDecrypt(long osslContextId, long gcmCtx,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws OpenSSLException;

    static public native int do_GCM_InitForUpdateEncrypt(long osslContextId, long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OpenSSLException;

    static public native int do_GCM_InitForUpdateDecrypt(long osslContextId, long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OpenSSLException;


    static public native void do_GCM_delete(long osslContextId) throws OpenSSLException;

    static public native void free_GCM_ctx(long osslContextId, long gcmContextId)
            throws OpenSSLException;

    //static public native int get_GCM_TLSEnabled() throws OpenSSLException;

    static public native long create_GCM_context(long osslContextId) throws OpenSSLException;

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    static public native long do_CCM_checkHardwareCCMSupport(long osslContextId);

    static public native int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OpenSSLException;

    static public native int do_CCM_encryptFastJNI(long osslContextId, int keyLen, int ivLen,
            int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws OpenSSLException;

    static public native int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OpenSSLException;

    static public native int do_CCM_decryptFastJNI(long osslContextId, int keyLen, int ivLen,
            int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws OpenSSLException;

    static public native int do_CCM_encrypt(long osslContextId, byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext,
            int ciphertextLen, int tagLen) throws OpenSSLException;

    static public native int do_CCM_decrypt(long osslContextId, byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength,
            byte[] plaintext, int plaintextLength, int tagLen) throws OpenSSLException;

    static public native void do_CCM_delete(long osslContextId) throws OpenSSLException;

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    static public native int RSACIPHER_public_encrypt(long osslContextId, long rsaKeyId,
            int rsaPaddingId, int mdId, int mgf1Id, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OpenSSLException;

    static public native int RSACIPHER_private_encrypt(long osslContextId, long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OpenSSLException;

    static public native int RSACIPHER_public_decrypt(long osslContextId, long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException;

    static public native int RSACIPHER_private_decrypt(long osslContextId, long rsaKeyId,
            int rsaPaddingId, int mdId, int mgf1Id, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset, boolean convertKey) throws OpenSSLException;

    // =========================================================================
    // DH key functions
    // =========================================================================

    static public native long DHKEY_generate(long osslContextId, int numBits) throws OpenSSLException;

    static public native byte[] DHKEY_generateParameters(long osslContextId, int numBits);

    static public native long DHKEY_generate(long osslContextId, byte[] dhParameters)
            throws OpenSSLException;

    static public native long DHKEY_createPrivateKey(long osslContextId, byte[] privateKeyBytes)
            throws OpenSSLException;

    static public native long DHKEY_createPublicKey(long osslContextId, byte[] publicKeyBytes)
            throws OpenSSLException;

    static public native byte[] DHKEY_getParameters(long osslContextId, long dhKeyId);

    static public native byte[] DHKEY_getPrivateKeyBytes(long osslContextId, long dhKeyId)
            throws OpenSSLException;

    static public native byte[] DHKEY_getPublicKeyBytes(long osslContextId, long dhKeyId)
            throws OpenSSLException;

    static public native long DHKEY_createPKey(long osslContextId, long dhKeyId) throws OpenSSLException;

    static public native byte[] DHKEY_computeDHSecret(long osslContextId, long pubKeyId,
            long privKeyId) throws OpenSSLException;

    static public native void DHKEY_delete(long osslContextId, long dhKeyId) throws OpenSSLException;

    // =========================================================================
    // RSA key functions
    // =========================================================================

    static public native long RSAKEY_generate(long osslContextId, int numBits, long e)
            throws OpenSSLException;

    static public native long RSAKEY_createPrivateKey(long osslContextId, byte[] privateKeyBytes)
            throws OpenSSLException;

    static public native long RSAKEY_createPublicKey(long osslContextId, byte[] publicKeyBytes)
            throws OpenSSLException;

    static public native byte[] RSAKEY_getPrivateKeyBytes(long osslContextId, long rsaKeyId)
            throws OpenSSLException;

    static public native byte[] RSAKEY_getPublicKeyBytes(long osslContextId, long rsaKeyId)
            throws OpenSSLException;

    static public native int RSAKEY_size(long osslContextId, long rsaKeyId);

    static public native void RSAKEY_delete(long osslContextId, long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    static public native long DSAKEY_generate(long osslContextId, int numBits) throws OpenSSLException;

    static public native byte[] DSAKEY_generateParameters(long osslContextId, int numBits);

    static public native long DSAKEY_generate(long osslContextId, byte[] dsaParameters)
            throws OpenSSLException;

    static public native long DSAKEY_createPrivateKey(long osslContextId, byte[] privateKeyBytes)
            throws OpenSSLException;

    static public native long DSAKEY_createPublicKey(long osslContextId, byte[] publicKeyBytes)
            throws OpenSSLException;

    static public native byte[] DSAKEY_getParameters(long osslContextId, long dsaKeyId);

    static public native byte[] DSAKEY_getPrivateKeyBytes(long osslContextId, long dsaKeyId)
            throws OpenSSLException;

    static public native byte[] DSAKEY_getPublicKeyBytes(long osslContextId, long dsaKeyId)
            throws OpenSSLException;

    static public native long DSAKEY_createPKey(long osslContextId, long dsaKeyId)
            throws OpenSSLException;

    static public native void DSAKEY_delete(long osslContextId, long dsaKeyId) throws OpenSSLException;

    // =========================================================================
    // PKey functions
    // =========================================================================

    static public native void PKEY_delete(long osslContextId, long pkeyId) throws OpenSSLException;

    // =========================================================================
    // Digest functions
    // =========================================================================

    static public native long DIGEST_create(long osslContextId, String digestAlgo)
            throws OpenSSLException;

    static public native long DIGEST_copy(long id, long digestId)
            throws OpenSSLException;

    static public native int DIGEST_update(long osslContextId, long digestId, byte[] input,
            int offset, int length) throws OpenSSLException;

    static public native void DIGEST_updateFastJNI(long osslContextId, long digestId,
            long inputBuffer, int length) throws OpenSSLException;

    static public native byte[] DIGEST_digest(long osslContextId, long digestId) throws OpenSSLException;

    static public native void DIGEST_digest_and_reset(long osslContextId, long digestId,
            long outputBuffer, int length) throws OpenSSLException;

    static public native int DIGEST_digest_and_reset(long osslContextId, long digestId,
            byte[] output) throws OpenSSLException;

    static public native int DIGEST_size(long osslContextId, long digestId) throws OpenSSLException;

    static public native void DIGEST_reset(long osslContextId, long digestId) throws OpenSSLException;

    static public native void DIGEST_delete(long osslContextId, long digestId) throws OpenSSLException;

    static public native int DIGEST_PKCS12KeyDeriveHelp(long osslContextId, long digestId, byte[] input,
            int offset, int length, int iterationCount) throws OpenSSLException;

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    static public native byte[] SIGNATURE_sign(long osslContextId, long digestId, long pkeyId,
            boolean convert) throws OpenSSLException;

    static public native boolean SIGNATURE_verify(long osslContextId, long digestId, long pkeyId,
            byte[] sigBytes) throws OpenSSLException;

    static public native byte[] SIGNATUREEdDSA_signOneShot(long osslContextId, long pkeyId,
            byte[] bytes) throws OpenSSLException;

    static public native boolean SIGNATUREEdDSA_verifyOneShot(long osslContextId, long pkeyId,
            byte[] sigBytes, byte[] oneShot) throws OpenSSLException;

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    static public native int RSAPSS_signInit(long osslContextId, long rsaPssId, long pkeyId,
            int saltlen, boolean convert) throws OpenSSLException;

    static public native int RSAPSS_verifyInit(long osslContextId, long rsaPssId, long pkeyId,
            int saltlen) throws OpenSSLException;

    static public native int RSAPSS_getSigLen(long osslContextId, long rsaPssId);

    static public native void RSAPSS_signFinal(long osslContextId, long rsaPssId, byte[] signature,
            int length) throws OpenSSLException;

    static public native boolean RSAPSS_verifyFinal(long osslContextId, long rsaPssId,
            byte[] sigBytes, int length) throws OpenSSLException;

    static public native long RSAPSS_createContext(long osslContextId, String digestAlgo,
            String mgf1SpecAlgo) throws OpenSSLException;

    static public native void RSAPSS_releaseContext(long osslContextId, long rsaPssId)
            throws OpenSSLException;

    static public native void RSAPSS_digestUpdate(long osslContextId, long rsaPssId, byte[] input,
            int offset, int length) throws OpenSSLException;

    static public native void RSAPSS_reset(long osslContextId, long digestId) throws OpenSSLException;

    static public native void RSAPSS_resetDigest(long osslContextId, long rsaPssId)
            throws OpenSSLException;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    static public native byte[] DSANONE_SIGNATURE_sign(long osslContextId, byte[] digest,
            long dsaKeyId) throws OpenSSLException;

    static public native boolean DSANONE_SIGNATURE_verify(long osslContextId, byte[] digest,
            long dsaKeyId, byte[] sigBytes) throws OpenSSLException;

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    static public native byte[] RSASSL_SIGNATURE_sign(long osslContextId, byte[] digest,
            long rsaKeyId) throws OpenSSLException;

    static public native boolean RSASSL_SIGNATURE_verify(long osslContextId, byte[] digest,
            long rsaKeyId, byte[] sigBytes, boolean convert) throws OpenSSLException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    static public native long HMAC_create(long osslContextId, String digestAlgo) throws OpenSSLException;

    static public native int HMAC_update(long osslContextId, long hmacId, byte[] key, int keyLength,
            byte[] input, int inputOffset, int inputLength, boolean needInit) throws OpenSSLException;

    static public native int HMAC_doFinal(long osslContextId, long hmacId, byte[] key, int keyLength,
            byte[] hmac, boolean needInit) throws OpenSSLException;

    static public native int HMAC_size(long osslContextId, long hmacId) throws OpenSSLException;

    static public native void HMAC_delete(long osslContextId, long hmacId) throws OpenSSLException;

    // =========================================================================
    // EC key functions
    // =========================================================================

    static public native long ECKEY_generate(long osslContextId, int numBits) throws OpenSSLException;

    static public native long ECKEY_generate(long osslContextId, String curveOid)
            throws OpenSSLException;

    static public native long XECKEY_generate(long osslContextId, int option, long bufferPtr)
            throws OpenSSLException;

    static public native byte[] ECKEY_generateParameters(long osslContextId, int numBits)
            throws OpenSSLException;

    static public native byte[] ECKEY_generateParameters(long osslContextId, String curveOid)
            throws OpenSSLException;

    static public native long ECKEY_generate(long osslContextId, byte[] ecParameters)
            throws OpenSSLException;

    static public native long ECKEY_createPrivateKey(long osslContextId, byte[] privateKeyBytes)
            throws OpenSSLException;

    static public native long XECKEY_createPrivateKey(long osslContextId, byte[] privateKeyBytes,
            long bufferPtr) throws OpenSSLException;

    static public native long ECKEY_createPublicKey(long osslContextId, byte[] publicKeyBytes,
            byte[] parameterBytes) throws OpenSSLException;

    static public native long XECKEY_createPublicKey(long osslContextId, byte[] publicKeyBytes)
            throws OpenSSLException;

    static public native byte[] ECKEY_getParameters(long osslContextId, long ecKeyId);

    static public native byte[] ECKEY_getPrivateKeyBytes(long osslContextId, long ecKeyId)
            throws OpenSSLException;

    static public native byte[] XECKEY_getPrivateKeyBytes(long osslContextId, long xecKeyId)
            throws OpenSSLException;

    static public native byte[] ECKEY_getPublicKeyBytes(long osslContextId, long ecKeyId)
            throws OpenSSLException;

    static public native byte[] XECKEY_getPublicKeyBytes(long osslContextId, long xecKeyId)
            throws OpenSSLException;

    static public native long ECKEY_createPKey(long osslContextId, long ecKeyId) throws OpenSSLException;

    static public native void ECKEY_delete(long osslContextId, long ecKeyId) throws OpenSSLException;

    static public native void XECKEY_delete(long osslContextId, long xecKeyId) throws OpenSSLException;

    static public native long XDHKeyAgreement_init(long osslContextId, long privId);

    static public native void XDHKeyAgreement_setPeer(long osslContextId, long genCtx, long pubId);

    static public native byte[] ECKEY_computeECDHSecret(long osslContextId, long pubEcKeyId,
            long privEcKeyId) throws OpenSSLException;

    static public native byte[] XECKEY_computeECDHSecret(long osslContextId, long genCtx,
            long pubEcKeyId, long privEcKeyId, int secrectBufferSize) throws OpenSSLException;

    static public native byte[] ECKEY_signDatawithECDSA(long osslContextId, byte[] digestBytes,
            int digestBytesLen, long ecPrivateKeyId) throws OpenSSLException;

    static public native boolean ECKEY_verifyDatawithECDSA(long osslContextId, byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId)
            throws OpenSSLException;


    // =========================================================================
    // HKDF functions
    // =========================================================================

    static public native long HKDF_create(long osslContextId, String digestAlgo) throws OpenSSLException;

    static public native byte[] HKDF_extract(long osslContextId, long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen) throws OpenSSLException;

    static public native byte[] HKDF_expand(long osslContextId, long hkdfId, byte[] prkBytes,
            long prkBytesLen, byte[] info, long infoLen, long okmLen) throws OpenSSLException;

    static public native byte[] HKDF_derive(long osslContextId, long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen)
            throws OpenSSLException;

    static public native void HKDF_delete(long osslContextId, long hkdfId) throws OpenSSLException;

    static public native int HKDF_size(long osslContextId, long hkdfId) throws OpenSSLException;

    // =========================================================================
    // Password based key derivation functions ( PBKDF )
    // =========================================================================

    static public native byte[] PBKDF2_derive(long osslContextId, String hashAlgorithm, byte[] password, byte[] salt,
            int iterations, int keyLength) throws OpenSSLException;

    // =========================================================================
    // ML-KEY key functions
    // =========================================================================

    static public native long MLKEY_generate(long osslContextId, String cipherName)
            throws OpenSSLException;

    static public native long MLKEY_createPrivateKey(long osslContextId, String cipherName, byte[] privateKeyBytes)
            throws OpenSSLException;

    static public native long MLKEY_createPublicKey(long osslContextId, String cipherName, byte[] publicKeyBytes)
            throws OpenSSLException;

    static public native byte[] MLKEY_getPrivateKeyBytes(long osslContextId, long mlkeyId)
            throws OpenSSLException;

    static public native byte[] MLKEY_getPublicKeyBytes(long osslContextId, long mlkeyId)
            throws OpenSSLException;

    static public native void MLKEY_delete(long osslContextId, long mlkeyId);

    // =========================================================================
    // Key Encapsulation functions
    // =========================================================================
    static public native void KEM_encapsulate(long osslContextId, long pKeyId, byte[] wrappedKey, byte[] randomKey)
            throws OpenSSLException;

    static public native byte[] KEM_decapsulate(long osslContextId, long pKeyId, byte[] wrappedKey)
            throws OpenSSLException;

    // =========================================================================
    // PQC Signture functions - for use with ML-DSA and ML-SLH
    // =========================================================================
    static public native byte[] PQC_SIGNATURE_sign(long osslContextId,  long pKeyId, byte[] data) 
            throws OpenSSLException;

    static public native boolean PQC_SIGNATURE_verify(long osslContextId, long pKeyId, byte[] sigBytes, byte[] data) 
            throws OpenSSLException;
}
