/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.ProviderException;
import sun.security.util.Debug;

@SuppressWarnings({"removal", "deprecation"})
final class NativeInterface {

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    // Whether OCK is dynamically loaded. If OCK is dynamically loaded,
    // we want to pre-load OCK to help ensure we are getting the expected
    // version.
    //
    private static final boolean ockDynamicallyLoaded = true;

    // If OCK is dynamically loaded, whether to require that OCK be
    // pre-loaded.
    //
    private static boolean requirePreloadOCK = true;

    // Default ock core library name
    //
    private static final String OCK_CORE_LIBRARY_NAME = "jgsk8iccs";
    private static final String JGSKIT_CORE_LIBRARY_NAME = "jgskit";
    private static String osName = null;
    private static String osArch = null;
    private static String JVMFIPSmode = null;

    static {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                if (ockDynamicallyLoaded) {
                    // Preload OCK library. We want to pre-load OCK to help
                    // ensure we are picking up the expected version within
                    // the JRE.
                    //
                    preloadOCK();
                }

                // Load native code for java-gskit
                //
                preloadJGskit();
                return null;
            }
        });
    }

    public static String getOsName() {
        return osName;
    }

    public static String getOsArch() {
        return osArch;

    }

    static String getOCKLoadPath() {
        String ockOverridePath = System.getProperty("ock.library.path");
        if (ockOverridePath != null) {
            if (debug != null) {
                debug.println("Loading ock library using value in property ock.library.path: "
                    + ockOverridePath);
            }
            return ockOverridePath;
        }
        if (debug != null) {
            debug.println("Library path not found for ock, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String ockPath;

        if (osName.startsWith("Windows")) {
            ockPath = javaHome + File.separator + "bin";
        } else {
            ockPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading ock library using value: " + ockPath);
        }
        return ockPath;
    }

    static String getJGskitLoadPath() {
        String jgskitOverridePath = System.getProperty("jgskit.library.path");
        if (jgskitOverridePath != null) {
            if (debug != null) {
                debug.println("Loading jgskit library using value in property jgskit.library.path: " + jgskitOverridePath);
            }
            return jgskitOverridePath;
        }
        if (debug != null) {
            debug.println("Libpath not found for jgskit, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String jgskitPath;

        if (osName.startsWith("Windows")) {
            jgskitPath = javaHome + File.separator + "bin";
        } else {
            jgskitPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading jgskit library using value: " + jgskitPath);
        }
        return jgskitPath;
    }

    static void preloadJGskit() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String jgskitPath = getJGskitLoadPath();
        File loadFile = null;
        if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + "_64.dll");
        } else if (osName.equals("Mac OS X")) {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + ".dylib");
        } else {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + ".so");
        }

        boolean jgskitLibraryPreloaded = loadIfExists(loadFile);
        if (jgskitLibraryPreloaded == false) {
            throw new ProviderException("Could not load dependent " + JGSKIT_CORE_LIBRARY_NAME + " library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    static void preloadOCK() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String ockPath = getOCKLoadPath();
        File loadFile = null;

        // --------------------------------------------------------------
        // Determine the OCK library to load for a given OS and architecture.
        //
        // AIX: lib<OCK_CORE_LIBRARY_NAME>_64.so
        // Linux aarch64: lib<OCK_CORE_LIBRARY_NAME>.dylib
        // Linux ppc64le: lib<OCK_CORE_LIBRARY_NAME>_64.so
        // Linux s390x: lib<OCK_CORE_LIBRARY_NAME>_64.so
        // Linux x86_64: lib<OCK_CORE_LIBRARY_NAME>_64.so
        // Mac OS X: lib<OCK_CORE_LIBRARY_NAME>_64.so
        // Windows* amd64: <OCK_CORE_LIBRARY_NAME>_64.dll
        // --------------------------------------------------------------
        if (osName.equals("Mac OS X")) {
            loadFile = new File(ockPath, "lib" + OCK_CORE_LIBRARY_NAME + ".dylib");
        } else if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(ockPath, OCK_CORE_LIBRARY_NAME + "_64.dll");
        } else {
            loadFile = new File(ockPath, "lib" + OCK_CORE_LIBRARY_NAME + "_64.so");
        }

        boolean ockLibraryPreloaded = loadIfExists(loadFile);
        if ((ockLibraryPreloaded == false) && requirePreloadOCK) {
            throw new ProviderException("Could not load dependent ock library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    private static boolean loadIfExists(File libraryFile) {
        String libraryName = libraryFile.getAbsolutePath();

        if (libraryFile.exists()) {
            // Need a try/catch block in case the library has already been
            // loaded by another ClassLoader
            //
            try {
                System.load(libraryName);
                if (debug != null) {
                    debug.println("Loaded : " + libraryName);
                }
                return true;
            } catch (Throwable t) {
                if (debug != null) {
                    debug.println("Failed to load : " + libraryName);
                }
            }
        } else {
            if (debug != null) {
                debug.println("Skipping load of " + libraryName);
            }
        }
        return false;
    }

    static void validateLibraryLocation(OCKContext context) throws ProviderException, OCKException {
        if (requirePreloadOCK == false) {
            // If we are not requiring OCK to be pre-loaded, then it does not need to be
            // loaded from the JRE location
            //
            return;
        }

        try {
            // Check to make sure that the OCK install path is within the JRE
            //
            String ockLoadPath = new File(getOCKLoadPath()).getCanonicalPath();
            String ockInstallPath = new File(context.getOCKInstallPath()).getCanonicalPath();

            if (debug != null) {
                debug.println("dependent library load path : " + ockLoadPath);
                debug.println("dependent library install path : " + ockInstallPath);
            }

            if (ockInstallPath.startsWith(ockLoadPath) == false) {
                String exceptionMessage = "Dependent library was loaded from an external location";

                if (debug != null) {
                    exceptionMessage = "Dependent library was loaded from " + ockInstallPath;
                }

                throw new ProviderException(exceptionMessage);
            }
        } catch (java.io.IOException e) {
            throw new ProviderException("Failed to validate dependent library", e);
        }
    }

    static void validateLibraryVersion(OCKContext context) throws ProviderException, OCKException {
        if (requirePreloadOCK == false) {
            // If we are not requiring OCK to be pre-loaded, then it does not need to be
            // a specific version
            //
            return;
        }

        String expectedVersion = getExpectedLibraryVersion(context);
        String actualVersion = context.getOCKVersion();

        if (expectedVersion == null) {
            throw new ProviderException(
                    "Could not not determine expected version of dependent library");
        } else if (expectedVersion.equals(actualVersion) == false) {
            throw new ProviderException("Expected depdendent library version " + expectedVersion
                    + ", got " + actualVersion);
        }
    }

    private static String getExpectedLibraryVersion(OCKContext context) {
        String ockLoadPath = getOCKLoadPath();
        String ockSigFileName;
        if (context.isFIPS()) {
            ockSigFileName = ockLoadPath + File.separator + "C" + File.separator + "icc"
                    + File.separator + "icclib" + File.separator + "ICCSIG.txt";
        } else {
            ockSigFileName = ockLoadPath + File.separator + "N" + File.separator + "icc"
                    + File.separator + "icclib" + File.separator + "ICCSIG.txt";
        }
        BufferedReader br = null;
        try {
            String line;
            String versionMarker = "# ICC Version ";
            br = new BufferedReader(new FileReader(ockSigFileName));
            while ((line = br.readLine()) != null) {
                if (line.startsWith(versionMarker)) {
                    String version = line.substring(versionMarker.length()).trim();
                    return version;
                }
            }
        } catch (Exception e) {
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception e) {
                }
            }
        }

        return null;
    }

    // =========================================================================
    // General functions
    // =========================================================================

    static public native String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    static public native long initializeOCK(boolean isFIPS) throws OCKException;

    static public native String CTX_getValue(long ockContextId, int valueId) throws OCKException;

    static native long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    static public native void RAND_nextBytes(long ockContextId, byte[] buffer) throws OCKException;

    static public native void RAND_setSeed(long ockContextId, byte[] seed) throws OCKException;

    static public native void RAND_generateSeed(long ockContextId, byte[] seed) throws OCKException;

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    static public native long EXTRAND_create(long ockContextId, String algName) throws OCKException;

    static public native void EXTRAND_nextBytes(long ockContextId, long ockPRNGContextId,
            byte[] buffer) throws OCKException;

    static public native void EXTRAND_setSeed(long ockContextId, long ockPRNGContextId, byte[] seed)
            throws OCKException;

    static public native void EXTRAND_delete(long ockContextId, long ockPRNGContextId)
            throws OCKException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    static public native long CIPHER_create(long ockContextId, String cipher) throws OCKException;

    static public native void CIPHER_init(long ockContextId, long ockCipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv) throws OCKException;

    static public native void CIPHER_clean(long ockContextId, long ockCipherId) throws OCKException;

    static public native void CIPHER_setPadding(long ockContextId, long ockCipherId, int paddingId)
            throws OCKException;

    static public native int CIPHER_getBlockSize(long ockContextId, long ockCipherId);

    static public native int CIPHER_getKeyLength(long ockContextId, long ockCipherId);

    static public native int CIPHER_getIVLength(long ockContextId, long ockCipherId);

    static public native int CIPHER_getOID(long ockContextId, long ockCipherId);

    static public native int CIPHER_encryptUpdate(long ockContextId, long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OCKException;

    static public native int CIPHER_decryptUpdate(long ockContextId, long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws OCKException;

    static public native int CIPHER_encryptFinal(long ockContextId, long ockCipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit)
            throws OCKException;

    static public native int CIPHER_decryptFinal(long ockContextId, long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws OCKException;

    static public native long checkHardwareSupport(long ockContextId);

    static public native void CIPHER_delete(long ockContextId, long ockCipherId)
            throws OCKException;

    static public native int z_kmc_native(byte[] input, int inputOffset, byte[] output,
            int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    static public native long POLY1305CIPHER_create(long ockContextId, String cipher)
            throws OCKException;

    static public native void POLY1305CIPHER_init(long ockContextId, long ockCipherId,
            int isEncrypt, byte[] key, byte[] iv) throws OCKException;

    static public native void POLY1305CIPHER_clean(long ockContextId, long ockCipherId)
            throws OCKException;

    static public native void POLY1305CIPHER_setPadding(long ockContextId, long ockCipherId,
            int paddingId) throws OCKException;

    static public native int POLY1305CIPHER_getBlockSize(long ockContextId, long ockCipherId);

    static public native int POLY1305CIPHER_getKeyLength(long ockContextId, long ockCipherId);

    static public native int POLY1305CIPHER_getIVLength(long ockContextId, long ockCipherId);

    static public native int POLY1305CIPHER_getOID(long ockContextId, long ockCipherId);

    static public native int POLY1305CIPHER_encryptUpdate(long ockContextId, long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset) throws OCKException;

    static public native int POLY1305CIPHER_decryptUpdate(long ockContextId, long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws OCKException;

    static public native int POLY1305CIPHER_encryptFinal(long ockContextId, long ockCipherId,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset,
            byte[] tag) throws OCKException;

    static public native int POLY1305CIPHER_decryptFinal(long ockContextId, long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, byte[] tag) throws OCKException;

    static public native void POLY1305CIPHER_delete(long ockContextId, long ockCipherId)
            throws OCKException;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    static public native long do_GCM_checkHardwareGCMSupport(long ockContextId);

    static public native int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    static public native int do_GCM_encryptFastJNI(long ockContextId, long gcmCtx, int keyLen,
            int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException;

    static public native int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    static public native int do_GCM_decryptFastJNI(long ockContextId, long gcmCtx, int keyLen,
            int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OCKException;

    static public native int do_GCM_encrypt(long ockContextId, long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OCKException;

    static public native int do_GCM_decrypt(long ockContextId, long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OCKException;

    static public native int do_GCM_FinalForUpdateEncrypt(long ockContextId, long gcmCtx,
            byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OCKException;

    static public native int do_GCM_FinalForUpdateDecrypt(long ockContextId, long gcmCtx,
            /* byte[] key, int keyLen,
             byte[] iv, int ivLen,*/
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OCKException;

    static public native int do_GCM_UpdForUpdateEncrypt(long ockContextId, long gcmCtx,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset)
            throws OCKException;

    static public native int do_GCM_UpdForUpdateDecrypt(long ockContextId, long gcmCtx,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws OCKException;

    static public native int do_GCM_InitForUpdateEncrypt(long ockContextId, long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OCKException;

    static public native int do_GCM_InitForUpdateDecrypt(long ockContextId, long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OCKException;


    static public native void do_GCM_delete(long ockContextId) throws OCKException;

    static public native void free_GCM_ctx(long ockContextId, long gcmContextId)
            throws OCKException;

    //static public native int get_GCM_TLSEnabled() throws OCKException;

    static public native long create_GCM_context(long ockContextId) throws OCKException;

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    static public native long do_CCM_checkHardwareCCMSupport(long ockContextId);

    static public native int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    static public native int do_CCM_encryptFastJNI(long ockContextId, int keyLen, int ivLen,
            int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws OCKException;

    static public native int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    static public native int do_CCM_decryptFastJNI(long ockContextId, int keyLen, int ivLen,
            int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws OCKException;

    static public native int do_CCM_encrypt(long ockContextId, byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext,
            int ciphertextLen, int tagLen) throws OCKException;

    static public native int do_CCM_decrypt(long ockContextId, byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength,
            byte[] plaintext, int plaintextLength, int tagLen) throws OCKException;

    static public native void do_CCM_delete(long ockContextId) throws OCKException;

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    static public native int RSACIPHER_public_encrypt(long ockContextId, long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OCKException;

    static public native int RSACIPHER_private_encrypt(long ockContextId, long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OCKException;

    static public native int RSACIPHER_public_decrypt(long ockContextId, long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset) throws OCKException;

    static public native int RSACIPHER_private_decrypt(long ockContextId, long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset, boolean convertKey) throws OCKException;

    // =========================================================================
    // DH key functions
    // =========================================================================

    static public native long DHKEY_generate(long ockContextId, int numBits) throws OCKException;

    static public native byte[] DHKEY_generateParameters(long ockContextId, int numBits);

    static public native long DHKEY_generate(long ockContextId, byte[] dhParameters)
            throws OCKException;

    static public native long DHKEY_createPrivateKey(long ockContextId, byte[] privateKeyBytes)
            throws OCKException;

    static public native long DHKEY_createPublicKey(long ockContextId, byte[] publicKeyBytes)
            throws OCKException;

    static public native byte[] DHKEY_getParameters(long ockContextId, long dhKeyId);

    static public native byte[] DHKEY_getPrivateKeyBytes(long ockContextId, long dhKeyId)
            throws OCKException;

    static public native byte[] DHKEY_getPublicKeyBytes(long ockContextId, long dhKeyId)
            throws OCKException;

    static public native long DHKEY_createPKey(long ockContextId, long dhKeyId) throws OCKException;

    static public native byte[] DHKEY_computeDHSecret(long ockContextId, long pubKeyId,
            long privKeyId) throws OCKException;

    static public native void DHKEY_delete(long ockContextId, long dhKeyId) throws OCKException;

    // =========================================================================
    // RSA key functions
    // =========================================================================

    static public native long RSAKEY_generate(long ockContextId, int numBits, long e)
            throws OCKException;

    static public native long RSAKEY_createPrivateKey(long ockContextId, byte[] privateKeyBytes)
            throws OCKException;

    static public native long RSAKEY_createPublicKey(long ockContextId, byte[] publicKeyBytes)
            throws OCKException;

    static public native byte[] RSAKEY_getPrivateKeyBytes(long ockContextId, long rsaKeyId)
            throws OCKException;

    static public native byte[] RSAKEY_getPublicKeyBytes(long ockContextId, long rsaKeyId)
            throws OCKException;

    static public native long RSAKEY_createPKey(long ockContextId, long rsaKeyId)
            throws OCKException;

    static public native int RSAKEY_size(long ockContextId, long rsaKeyId);

    static public native void RSAKEY_delete(long ockContextId, long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    static public native long DSAKEY_generate(long ockContextId, int numBits) throws OCKException;

    static public native byte[] DSAKEY_generateParameters(long ockContextId, int numBits);

    static public native long DSAKEY_generate(long ockContextId, byte[] dsaParameters)
            throws OCKException;

    static public native long DSAKEY_createPrivateKey(long ockContextId, byte[] privateKeyBytes)
            throws OCKException;

    static public native long DSAKEY_createPublicKey(long ockContextId, byte[] publicKeyBytes)
            throws OCKException;

    static public native byte[] DSAKEY_getParameters(long ockContextId, long dsaKeyId);

    static public native byte[] DSAKEY_getPrivateKeyBytes(long ockContextId, long dsaKeyId)
            throws OCKException;

    static public native byte[] DSAKEY_getPublicKeyBytes(long ockContextId, long dsaKeyId)
            throws OCKException;

    static public native long DSAKEY_createPKey(long ockContextId, long dsaKeyId)
            throws OCKException;

    static public native void DSAKEY_delete(long ockContextId, long dsaKeyId) throws OCKException;

    // =========================================================================
    // PKey functions
    // =========================================================================

    static public native void PKEY_delete(long ockContextId, long pkeyId) throws OCKException;

    // =========================================================================
    // Digest functions
    // =========================================================================

    static public native long DIGEST_create(long ockContextId, String digestAlgo)
            throws OCKException;

    static public native long DIGEST_copy(long id, long digestId)
            throws OCKException;

    static public native int DIGEST_update(long ockContextId, long digestId, byte[] input,
            int offset, int length) throws OCKException;

    static public native void DIGEST_updateFastJNI(long ockContextId, long digestId,
            long inputBuffer, int length) throws OCKException;

    static public native byte[] DIGEST_digest(long ockContextId, long digestId) throws OCKException;

    static public native void DIGEST_digest_and_reset(long ockContextId, long digestId,
            long outputBuffer, int length) throws OCKException;

    static public native int DIGEST_digest_and_reset(long ockContextId, long digestId,
            byte[] output) throws OCKException;

    static public native int DIGEST_size(long ockContextId, long digestId) throws OCKException;

    static public native void DIGEST_reset(long ockContextId, long digestId) throws OCKException;

    static public native void DIGEST_delete(long ockContextId, long digestId) throws OCKException;

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    static public native byte[] SIGNATURE_sign(long ockContextId, long digestId, long pkeyId,
            boolean convert) throws OCKException;

    static public native boolean SIGNATURE_verify(long ockContextId, long digestId, long pkeyId,
            byte[] sigBytes) throws OCKException;

    static public native byte[] SIGNATUREEdDSA_signOneShot(long ockContextId, long pkeyId,
            byte[] bytes) throws OCKException;

    static public native boolean SIGNATUREEdDSA_verifyOneShot(long ockContextId, long pkeyId,
            byte[] sigBytes, byte[] oneShot) throws OCKException;

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    static public native int RSAPSS_signInit(long ockContextId, long rsaPssId, long pkeyId,
            int saltlen, boolean convert) throws OCKException;

    static public native int RSAPSS_verifyInit(long ockContextId, long rsaPssId, long pkeyId,
            int saltlen) throws OCKException;

    static public native int RSAPSS_getSigLen(long ockContextId, long rsaPssId);

    static public native void RSAPSS_signFinal(long ockContextId, long rsaPssId, byte[] signature,
            int length) throws OCKException;

    static public native boolean RSAPSS_verifyFinal(long ockContextId, long rsaPssId,
            byte[] sigBytes, int length) throws OCKException;

    static public native long RSAPSS_createContext(long ockContextId, String digestAlgo,
            String mgf1SpecAlgo) throws OCKException;

    static public native void RSAPSS_releaseContext(long ockContextId, long rsaPssId)
            throws OCKException;

    static public native void RSAPSS_digestUpdate(long ockContextId, long rsaPssId, byte[] input,
            int offset, int length) throws OCKException;

    static public native void RSAPSS_reset(long ockContextId, long digestId) throws OCKException;

    static public native void RSAPSS_resetDigest(long ockContextId, long rsaPssId)
            throws OCKException;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    static public native byte[] DSANONE_SIGNATURE_sign(long ockContextId, byte[] digest,
            long dsaKeyId) throws OCKException;

    static public native boolean DSANONE_SIGNATURE_verify(long ockContextId, byte[] digest,
            long dsaKeyId, byte[] sigBytes) throws OCKException;

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    static public native byte[] RSASSL_SIGNATURE_sign(long ockContextId, byte[] digest,
            long rsaKeyId) throws OCKException;

    static public native boolean RSASSL_SIGNATURE_verify(long ockContextId, byte[] digest,
            long rsaKeyId, byte[] sigBytes, boolean convert) throws OCKException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    static public native long HMAC_create(long ockContextId, String digestAlgo) throws OCKException;

    static public native int HMAC_update(long ockContextId, long hmacId, byte[] key, int keyLength,
            byte[] input, int inputOffset, int inputLength, boolean needInit) throws OCKException;

    static public native int HMAC_doFinal(long ockContextId, long hmacId, byte[] key, int keyLength,
            byte[] hmac, boolean needInit) throws OCKException;

    static public native int HMAC_size(long ockContextId, long hmacId) throws OCKException;

    static public native void HMAC_delete(long ockContextId, long hmacId) throws OCKException;

    // =========================================================================
    // EC key functions
    // =========================================================================

    static public native long ECKEY_generate(long ockContextId, int numBits) throws OCKException;

    static public native long ECKEY_generate(long ockContextId, String curveOid)
            throws OCKException;

    static public native long XECKEY_generate(long ockContextId, int option, long bufferPtr)
            throws OCKException;

    static public native byte[] ECKEY_generateParameters(long ockContextId, int numBits)
            throws OCKException;

    static public native byte[] ECKEY_generateParameters(long ockContextId, String curveOid)
            throws OCKException;

    static public native long ECKEY_generate(long ockContextId, byte[] ecParameters)
            throws OCKException;

    static public native long ECKEY_createPrivateKey(long ockContextId, byte[] privateKeyBytes)
            throws OCKException;

    static public native long XECKEY_createPrivateKey(long ockContextId, byte[] privateKeyBytes,
            long bufferPtr) throws OCKException;

    static public native long ECKEY_createPublicKey(long ockContextId, byte[] publicKeyBytes,
            byte[] parameterBytes) throws OCKException;

    static public native long XECKEY_createPublicKey(long ockContextId, byte[] publicKeyBytes)
            throws OCKException;

    static public native byte[] ECKEY_getParameters(long ockContextId, long ecKeyId);

    static public native byte[] ECKEY_getPrivateKeyBytes(long ockContextId, long ecKeyId)
            throws OCKException;

    static public native byte[] XECKEY_getPrivateKeyBytes(long ockContextId, long xecKeyId)
            throws OCKException;

    static public native byte[] ECKEY_getPublicKeyBytes(long ockContextId, long ecKeyId)
            throws OCKException;

    static public native byte[] XECKEY_getPublicKeyBytes(long ockContextId, long xecKeyId)
            throws OCKException;

    static public native long ECKEY_createPKey(long ockContextId, long ecKeyId) throws OCKException;

    static public native void ECKEY_delete(long ockContextId, long ecKeyId) throws OCKException;

    static public native void XECKEY_delete(long ockContextId, long xecKeyId) throws OCKException;

    static public native long XDHKeyAgreement_init(long ockContextId, long privId);

    static public native void XDHKeyAgreement_setPeer(long ockContextId, long genCtx, long pubId);

    static public native byte[] ECKEY_computeECDHSecret(long ockContextId, long pubEcKeyId,
            long privEcKeyId) throws OCKException;

    static public native byte[] XECKEY_computeECDHSecret(long ockContextId, long genCtx,
            long pubEcKeyId, long privEcKeyId, int secrectBufferSize) throws OCKException;


    static public native byte[] ECKEY_signDatawithECDSA(long ockContextId, byte[] digestBytes,
            int digestBytesLen, long ecPrivateKeyId) throws OCKException;

    static public native boolean ECKEY_verifyDatawithECDSA(long ockContextId, byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId)
            throws OCKException;


    // =========================================================================
    // HKDF functions
    // =========================================================================

    static public native long HKDF_create(long ockContextId, String digestAlgo) throws OCKException;

    static public native byte[] HKDF_extract(long ockContextId, long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen) throws OCKException;

    static public native byte[] HKDF_expand(long ockContextId, long hkdfId, byte[] prkBytes,
            long prkBytesLen, byte[] info, long infoLen, long okmLen) throws OCKException;

    static public native byte[] HKDF_derive(long ockContextId, long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen)
            throws OCKException;

    static public native void HKDF_delete(long ockContextId, long hkdfId) throws OCKException;

    static public native int HKDF_size(long ockContextId, long hkdfId) throws OCKException;
}
