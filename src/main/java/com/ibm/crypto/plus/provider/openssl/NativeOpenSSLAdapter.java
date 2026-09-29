/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeInterface;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;
import javax.crypto.BadPaddingException;
import sun.security.util.Debug;

public abstract class NativeOpenSSLAdapter implements NativeInterface {
    // These code values must match those defined in StaticStub.c.
    //
    private static final int VALUE_OSSL_INSTALL_PATH = 1;
    private static final int VALUE_OSSL_VERSION = 2;

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    static final String unobtainedValue = new String();

    private static final int DEFAULT_GCM_TAG_LEN = 16;
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    private OpenSSLContext osslContext = null;
    private boolean osslInitialized = false;
    private boolean useFIPSMode;

    private static final String minOpenSSLVersion = "3.5.0";

    // unobtainedValue sentinel: identity (==) comparison detects "not yet fetched".
    // Some values may be null once fetched, so we cannot use null as the sentinel.
    private String osslVersion = unobtainedValue;
    private String osslInstallPath = unobtainedValue;

    // Same sentinel for the static build-date string.
    private static String libraryBuildDate = unobtainedValue;

    NativeOpenSSLAdapter(boolean useFIPSMode) {
        this.useFIPSMode = useFIPSMode;
        initializeContext();
    }

    // Initialize OpenSSL context(s)
    //
    private synchronized void initializeContext() {
        // Leave this duplicate check in here. If two threads are both trying
        // to instantiate an OpenJCEPlus provider at the same time, we need to
        // ensure that the initialization only happens one time. We have
        // made the method synchronized to ensure only one thread can execute
        // the method at a time.
        //
        if (osslInitialized) {
            return;
        }

        try {
            long osslContextId =  NativeOpenSSLImplementation.initializeOSSL(this.useFIPSMode);
            this.osslContext = OpenSSLContext.createContext(osslContextId, this.useFIPSMode);
            getLibraryBuildDate();

            this.osslInitialized = true;
        } catch (OpenSSLException e) {
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

    // Get OpenSSL context for crypto operations
    //
    OpenSSLContext getOpenSSLContext() {
        // May need to initialize OpenSSL here in the case that a serialized
        // OpenJCEPlus object, such as a HASHDRBG SecureRandom, is being
        // deserialized in a JVM that has not instantiated the OpenJCEPlus
        // provider yet.
        //
        if (!osslInitialized) {
            initializeContext();
        }

        return osslContext;
    }

    @Override
    public String getLibraryVersion() throws OpenSSLException {
        if (osslVersion == unobtainedValue) {
            obtainOpenSSLVersion();
        }
        return osslVersion;
    }

    @Override
    public String getLibraryInstallPath() throws OpenSSLException {
        if (osslInstallPath == unobtainedValue) {
            obtainOpenSSLInstallPath();
        }
        return osslInstallPath;
    }

    private synchronized void obtainOpenSSLVersion() throws OpenSSLException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (osslVersion == unobtainedValue) {
            osslVersion = CTX_getValue(VALUE_OSSL_VERSION);
        }
    }

    private synchronized void obtainOpenSSLInstallPath() throws OpenSSLException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (osslInstallPath == unobtainedValue) {
            osslInstallPath = CTX_getValue(VALUE_OSSL_INSTALL_PATH);
        }
    }

    static public ProviderException providerException(String message, Throwable throwable) {
        return new ProviderException(message, throwable);
    }

    /**
     * Validates that the OpenSSL install path is within the JRE directory.
     * Not called during normal initialisation (OpenSSL ships separately from the JRE);
     * retained to satisfy the {@link com.ibm.crypto.plus.provider.base.NativeInterface} contract.
     */
    @Override
    public void validateLibraryLocation() throws ProviderException, OpenSSLException {
        try {
            // Check to make sure that the OpenSSL install path is within the JRE
            //
            String osslLoadPath = NativeOpenSSLImplementation.getOSSLLoadFile().getCanonicalPath();
            String osslInstallPath = new File(getLibraryInstallPath()).getCanonicalPath();

            if (debug != null) {
                debug.println("dependent library load path : " + osslLoadPath);
                debug.println("dependent library install path : " + osslInstallPath);
            }

            if (!osslInstallPath.startsWith(osslLoadPath)) {
                throw new ProviderException("Dependent library was loaded from " + osslLoadPath
                        + " but config files are from " + osslInstallPath);
            }
        } catch (java.io.IOException e) {
            throw new ProviderException("Incorrect file specification for dependent library", e);
        }
    }

    @Override
    public void validateLibraryVersion() throws ProviderException, OpenSSLException {
        String[] minimumVersion = getMinimumLibraryVersion().split("\\.");
        String[] actualVersion = getLibraryVersion().split("\\.");

        if (debug != null) {
            debug.println("Minimum OpenSSL version : " + getMinimumLibraryVersion());
            debug.println("Actual OpenSSL version : " + getLibraryVersion());
        }

        int majorExpected = Integer.parseInt(minimumVersion[0]);
        int majorActual = Integer.parseInt(actualVersion[0]);
        int minorExpected = Integer.parseInt(minimumVersion[1]);
        int minorActual = Integer.parseInt(actualVersion[1]);
        int patchExpected = Integer.parseInt(minimumVersion[2]);
        int patchActual = Integer.parseInt(actualVersion[2]);

        if (majorExpected > majorActual) {
            throw new ProviderException("Expected OpenSSL library version greater than " + minimumVersion
                    + ", got " + actualVersion);
        } else if (majorExpected == majorActual) {
            if (minorExpected > minorActual) {
                throw new ProviderException("Expected OpenSSL library version greater than " + minimumVersion
                    + ", got " + actualVersion);
            } else if ((minorExpected == minorActual) && (patchExpected > patchActual)) {
                throw new ProviderException("Expected OpenSSL library version greater than " + minimumVersion
                        + ", got " + actualVersion);
            }
        }
    }

    private String getMinimumLibraryVersion() {
        return minOpenSSLVersion;
    }

    @Override
    public String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeOpenSSLImplementation.getLibraryBuildDate();
        }
        return libraryBuildDate;
    }

    /**
     * No-op for the OpenSSL backend. Context initialisation is performed in
     * {@link #initializeContext()} during construction; this method exists solely
     * to satisfy the {@link com.ibm.crypto.plus.provider.base.NativeInterface} contract.
     */
    @Override
    public long initialize(boolean isFIPS) throws OpenSSLException {
        return 0;
    }

    @Override
    public String CTX_getValue(int valueId) throws OpenSSLException {
        return NativeOpenSSLImplementation.CTX_getValue(osslContext.getId(), valueId);
    }

    @Override
    public long getByteBufferPointer(ByteBuffer b) {
        return NativeOpenSSLImplementation.getByteBufferPointer(b);
    }

    @Override
    public void RAND_nextBytes(byte[] buffer) throws OpenSSLException {
        NativeOpenSSLImplementation.RAND_nextBytes(osslContext.getId(), buffer);
    }

    @Override
    public void RAND_setSeed(byte[] seed) throws OpenSSLException {
        NativeOpenSSLImplementation.RAND_setSeed(osslContext.getId(), seed);
    }

    @Override
    public void RAND_generateSeed(byte[] seed) throws OpenSSLException {
        NativeOpenSSLImplementation.RAND_generateSeed(osslContext.getId(), seed);
    }

    @Override
    public long EXTRAND_create(String algName) throws OpenSSLException {
        return NativeOpenSSLImplementation.EXTRAND_create(osslContext.getId(), algName);
    }

    @Override
    public void EXTRAND_nextBytes(long PRNGContextId, byte[] buffer) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_nextBytes(osslContext.getId(), PRNGContextId, buffer);
    }

    @Override
    public void EXTRAND_setSeed(long PRNGContextId, byte[] seed) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_setSeed(osslContext.getId(), PRNGContextId, seed);
    }

    @Override
    public void EXTRAND_delete(long PRNGContextId) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_delete(osslContext.getId(), PRNGContextId);
    }

    @Override
    public long CIPHER_create(String cipher) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_create(osslContext.getId(), cipher);
    }

    @Override
    public void CIPHER_init(long cipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_init(osslContext.getId(), cipherId, isEncrypt, paddingId, key, iv);
    }

    @Override
    public void CIPHER_clean(long cipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_clean(osslContext.getId(), cipherId);
    }

    @Override
    public void CIPHER_setPadding(long cipherId, int paddingId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_setPadding(osslContext.getId(), cipherId, paddingId);
    }

    @Override
    public int CIPHER_getBlockSize(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getBlockSize(osslContext.getId(), cipherId);
    }

    @Override
    public int CIPHER_getKeyLength(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getKeyLength(osslContext.getId(), cipherId);
    }

    @Override
    public int CIPHER_getIVLength(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getIVLength(osslContext.getId(), cipherId);
    }

    @Override
    public int CIPHER_getOID(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getOID(osslContext.getId(), cipherId);
    }

    @Override
    public int CIPHER_encryptUpdate(long cipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_encryptUpdate(osslContext.getId(), cipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptUpdate(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_decryptUpdate(osslContext.getId(), cipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public int CIPHER_encryptFinal(long cipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_encryptFinal(osslContext.getId(), cipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptFinal(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit)
            throws OpenSSLException, BadPaddingException {
        try {
            return NativeOpenSSLImplementation.CIPHER_decryptFinal(osslContext.getId(), cipherId,
                ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
        } catch (OpenSSLException e) {
            // OpenSSL reports PKCS padding errors as a native exception whose message
            // contains "bad padding". Translate to BadPaddingException so callers that
            // declare 'catch (BadPaddingException)' behave correctly, matching OCK semantics.
            String msg = e.getMessage();
            if (msg != null && msg.toLowerCase().contains("bad padding")) {
                BadPaddingException bpe = new BadPaddingException(msg);
                bpe.initCause(e);
                throw bpe;
            }
            throw e;
        }
    }

    @Override
    public long checkHardwareSupport() {
        // OpenSSL handles hardware acceleration internally (e.g., AES-NI on x86).
        // No z/OS-specific KMC hardware support on this platform.
        return 0;
    }

    @Override
    public void CIPHER_delete(long cipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_delete(osslContext.getId(), cipherId);
    }

    @Override
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_KeyWraporUnwrap(osslContext.getId(), key, KEK, type);
    }

    @Override
    public int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer,
            int inputLength, int mode) {
        throw new UnsupportedOperationException("z_kmc_native not supported on OpenSSL backend (no z/arch hardware)");
    }

    @Override
    public long POLY1305CIPHER_create(String cipher) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_create not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_init(long cipherId, int isEncrypt, byte[] key, byte[] iv) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_init not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_clean(long cipherId) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_clean not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_setPadding(long cipherId, int paddingId) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_setPadding not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getBlockSize(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getBlockSize not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getKeyLength(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getKeyLength not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getIVLength(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getIVLength not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getOID(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getOID not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_encryptUpdate(long cipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_encryptUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_decryptUpdate(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_decryptUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_encryptFinal(long cipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] tag) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_encryptFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_decryptFinal(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] tag) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_decryptFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_delete(long cipherId) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // GCM Functions - implemented in Java over thin JNI primitives
    // =========================================================================

    @Override
    public long do_GCM_checkHardwareGCMSupport() {
        // No z/OS-style hardware GCM support on x86; OpenSSL uses AES-NI internally.
        return -1;
    }

    @Override
    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_encryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset,
            int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_encryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_decryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen,
            int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_decryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset,
            int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OpenSSLException {
        if (ciphertextOffset < 0 || inLen < 0 || ciphertextOffset + inLen > ciphertext.length) {
            throw new OpenSSLException("GCM encrypt: ciphertext buffer too small or invalid offset");
        }
        if (tagLen < 0 || tagLen > tag.length) {
            throw new OpenSSLException("GCM encrypt: tag buffer too small");
        }
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM encrypt: key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            // Native GCM_init requires tagLen >= 4 bytes. Clamp up for the native call;
            // only the requested tagLen bytes are returned to the caller.
            int nativeTagLen = Math.max(tagLen, 4);
            NativeOpenSSLImplementation.GCM_init(osslContext.getId(), gcmCtx, 1, key, iv, nativeTagLen);
            byte[] combinedOutput = new byte[inLen + nativeTagLen];
            int totalLen = NativeOpenSSLImplementation.GCM_encryptFinal(osslContext.getId(), gcmCtx,
                    input, inOffset, inLen, combinedOutput, 0, aad, aadLen, nativeTagLen);
            int cipherLen = Math.max(0, totalLen - nativeTagLen);
            System.arraycopy(combinedOutput, 0, ciphertext, ciphertextOffset, cipherLen);
            System.arraycopy(combinedOutput, cipherLen, tag, 0, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid GCM encryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during GCM encryption: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext,
            int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException {
        if (cipherOffset < 0 || cipherLen < 0 || tagLen < 0 ||
                cipherOffset + cipherLen + tagLen > ciphertext.length) {
            throw new OpenSSLException("GCM decrypt: ciphertext buffer too small or invalid offset/length");
        }
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM decrypt: key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            // Native GCM_init requires tagLen >= 4 bytes. Clamp up; only tagLen bytes of
            // ciphertext are the actual tag - pad with zeros if the tag is short.
            int nativeTagLen = Math.max(tagLen, 4);
            byte[] combinedInput = new byte[cipherLen + nativeTagLen];
            System.arraycopy(ciphertext, cipherOffset, combinedInput, 0, cipherLen);
            System.arraycopy(ciphertext, cipherOffset + cipherLen, combinedInput, cipherLen, tagLen);
            // remaining bytes (nativeTagLen - tagLen) are zero-padded, which is acceptable
            // because GCM tag verification is truncated to tagLen by OpenSSL
            NativeOpenSSLImplementation.GCM_init(osslContext.getId(), gcmCtx, 0, key, iv, nativeTagLen);
            NativeOpenSSLImplementation.GCM_decryptFinal(osslContext.getId(), gcmCtx,
                    combinedInput, 0, combinedInput.length, plaintext, plaintextOffset, aad, aadLen, nativeTagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid GCM decryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during GCM decryption: " + e.getMessage(), e);
        }
    }

    /**
     * Completes a multi-part GCM encryption (the "FinalForUpdate" path).
     *
     * <p>The {@code aad} parameter is intentionally ignored here.  AAD was already fed
     * to the OpenSSL context during {@link #do_GCM_InitForUpdateEncrypt} via a zero-length
     * GCM_update call.  Re-applying it in final would produce an incorrect authentication
     * tag.  GCMCipher previously tracked an {@code initCalled} flag and set {@code aad = null}
     * before this call; that flag has been removed and the suppression is handled here.
     */
    @Override
    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag,
            int tagLen) throws OpenSSLException {
        // AAD was already consumed in do_GCM_InitForUpdateEncrypt; ignore aad here.
        try {
            int totalLen = NativeOpenSSLImplementation.GCM_encryptFinal(osslContext.getId(), gcmCtx,
                    input, inOffset, inLen, ciphertext, ciphertextOffset, null, 0, tagLen);
            if (totalLen != inLen + tagLen) {
                throw new OpenSSLException("GCM encrypt final: unexpected output length " + totalLen
                        + " (expected " + (inLen + tagLen) + ")");
            }
            System.arraycopy(ciphertext, ciphertextOffset + inLen, tag, 0, tagLen);
            return 0;
        } catch (OpenSSLException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenSSLException(e.getMessage(), e);
        }
    }

    /**
     * Completes a multi-part GCM decryption (the "FinalForUpdate" path).
     *
     * <p>The {@code aad} parameter is intentionally ignored here - see
     * {@link #do_GCM_FinalForUpdateEncrypt} for the rationale.
     *
     * <p>Tag-mismatch detection: the OCK backend returned a negative {@code rc} which
     * GCMCipher previously checked and mapped to {@link javax.crypto.AEADBadTagException}.
     * The OpenSSL backend instead throws an {@link OpenSSLException} directly from
     * {@code GCM_decryptFinal}; that exception propagates up unchanged, so the caller
     * does not need to check a return code for the tag-mismatch case.
     */
    @Override
    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException {
        // AAD was already consumed in do_GCM_InitForUpdateDecrypt; ignore aad here.
        // A tag-mismatch from OpenSSL surfaces as an exception from GCM_decryptFinal.
        try {
            NativeOpenSSLImplementation.GCM_decryptFinal(osslContext.getId(), gcmCtx,
                    ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, null, 0, tagLen);
            return 0;
        } catch (OpenSSLException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenSSLException("GCM decrypt final failed: " + e.getMessage(), e);
        }
    }

    /**
     * Streams plaintext bytes through the active GCM encrypt context.
     *
     * <p>A negative return from {@code GCM_update} is treated as a hard failure and
     * thrown as {@link OpenSSLException}.  The OCK backend never returns negative values
     * from update calls, so this check is OpenSSL-specific; GCMCipher relies on a non-zero
     * {@code rc} to detect errors and throw {@link com.ibm.crypto.plus.provider.base.NativeException}.
     */
    @Override
    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset) throws OpenSSLException {
        try {
            int outLen = NativeOpenSSLImplementation.GCM_update(osslContext.getId(), gcmCtx, 1,
                    input, inOffset, inLen, ciphertext, ciphertextOffset, null, 0);
            if (outLen < 0) {
                throw new OpenSSLException("GCM update (encrypt) failed with code: " + outLen);
            }
            return 0;
        } catch (OpenSSLException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenSSLException(e.getMessage(), e);
        }
    }

    /**
     * Streams ciphertext bytes through the active GCM decrypt context.
     *
     * <p>Same negative-rc handling as {@link #do_GCM_UpdForUpdateEncrypt}; a negative
     * return from {@code GCM_update} throws {@link OpenSSLException} immediately rather
     * than propagating a non-zero integer to the caller.
     */
    @Override
    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        try {
            int outLen = NativeOpenSSLImplementation.GCM_update(osslContext.getId(), gcmCtx, 0,
                    ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, null, 0);
            if (outLen < 0) {
                throw new OpenSSLException("GCM update (decrypt) failed with code: " + outLen);
            }
            return 0;
        } catch (OpenSSLException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenSSLException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OpenSSLException {
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM init (update encrypt): key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            NativeOpenSSLImplementation.GCM_init(osslContext.getId(), gcmCtx, 1, key, iv, DEFAULT_GCM_TAG_LEN);
            if (aad != null && aadLen > 0) {
                NativeOpenSSLImplementation.GCM_update(osslContext.getId(), gcmCtx, 1,
                        EMPTY_BYTE_ARRAY, 0, 0, EMPTY_BYTE_ARRAY, 0, aad, aadLen);
            }
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException("GCM init for update encrypt failed: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OpenSSLException {
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM init (update decrypt): key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            NativeOpenSSLImplementation.GCM_init(osslContext.getId(), gcmCtx, 0, key, iv, DEFAULT_GCM_TAG_LEN);
            if (aad != null && aadLen > 0) {
                NativeOpenSSLImplementation.GCM_update(osslContext.getId(), gcmCtx, 0,
                        EMPTY_BYTE_ARRAY, 0, 0, EMPTY_BYTE_ARRAY, 0, aad, aadLen);
            }
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException("GCM init for update decrypt failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void do_GCM_delete() throws OpenSSLException {
        // No-op for OpenSSL backend - GCM contexts are managed explicitly via create/free.
    }

    @Override
    public void free_GCM_ctx(long gcmContextId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_delete(osslContext.getId(), gcmContextId);
    }

    @Override
    public long create_GCM_context() throws OpenSSLException {
        // Default to AES-128-GCM; key size is set properly on first GCM_init call.
        return NativeOpenSSLImplementation.CIPHER_create(osslContext.getId(), "AES-128-GCM");
    }

    @Override
    public long create_GCM_context(int keySize) throws OpenSSLException {
        String cipherName;
        switch (keySize) {
            case 16: cipherName = "AES-128-GCM"; break;
            case 24: cipherName = "AES-192-GCM"; break;
            case 32: cipherName = "AES-256-GCM"; break;
            default: cipherName = "AES-128-GCM"; break;
        }
        return NativeOpenSSLImplementation.CIPHER_create(osslContext.getId(), cipherName);
    }

    // =========================================================================
    // CCM Functions - implemented in Java over thin JNI primitives
    // =========================================================================

    @Override
    public long do_CCM_checkHardwareCCMSupport() {
        // No z/OS-style hardware CCM support on x86.
        return -1;
    }

    @Override
    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_encryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_CCM_encryptFastJNI(int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_encryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_decryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_CCM_decryptFastJNI(int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_decryptFastJNI not supported by OpenSSL backend");
    }

    private String getAESCipherAlgorithm(int keyLen, String mode) {
        switch (keyLen) {
            case 16: return "AES-128-" + mode;
            case 24: return "AES-192-" + mode;
            case 32: return "AES-256-" + mode;
            default: throw new IllegalArgumentException("Invalid AES key length: " + keyLen);
        }
    }

    @Override
    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input,
            int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) throws OpenSSLException {
        if (ciphertext.length < inLen + tagLen) {
            throw new OpenSSLException("CCM encrypt: ciphertext buffer too small (need "
                    + (inLen + tagLen) + " bytes, have " + ciphertext.length + ")");
        }
        long cipherId = NativeOpenSSLImplementation.CIPHER_create(osslContext.getId(),
                getAESCipherAlgorithm(keyLen, "CCM"));
        try {
            NativeOpenSSLImplementation.CCM_init(osslContext.getId(), cipherId, 1, key, iv, tagLen);
            NativeOpenSSLImplementation.CCM_encryptFinal(osslContext.getId(),
                    cipherId, input, 0, inLen, ciphertext, 0, aad, aadLen, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid CCM encryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during CCM encryption: " + e.getMessage(), e);
        } finally {
            NativeOpenSSLImplementation.CIPHER_delete(osslContext.getId(), cipherId);
        }
    }

    @Override
    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen,
            byte[] ciphertext, int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen)
            throws OpenSSLException {
        long cipherId = NativeOpenSSLImplementation.CIPHER_create(osslContext.getId(),
                getAESCipherAlgorithm(keyLen, "CCM"));
        try {
            NativeOpenSSLImplementation.CCM_init(osslContext.getId(), cipherId, 0, key, iv, tagLen);
            NativeOpenSSLImplementation.CCM_decryptFinal(osslContext.getId(),
                    cipherId, ciphertext, 0, ciphertextLength, plaintext, 0, aad, aadLen, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid CCM decryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during CCM decryption: " + e.getMessage(), e);
        } finally {
            NativeOpenSSLImplementation.CIPHER_delete(osslContext.getId(), cipherId);
        }
    }

    @Override
    public void do_CCM_delete() throws OpenSSLException {
        // No-op for OpenSSL backend - contexts are managed per-operation.
    }

    @Override
    public int RSACIPHER_public_encrypt(long rsaKeyId,
            int rsaPaddingId, int mdId, int mgf1Id, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSACIPHER_public_encrypt(osslContext.getId(), rsaKeyId, rsaPaddingId,
            mdId, mgf1Id, plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int RSACIPHER_private_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSACIPHER_private_encrypt(osslContext.getId(), rsaKeyId, rsaPaddingId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, convertKey);
    }

    @Override
    public int RSACIPHER_public_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSACIPHER_public_decrypt(osslContext.getId(), rsaKeyId, rsaPaddingId,
            ciphertext, ciphertextOffset, ciphertextLen, plaintext, plaintextOffset);
    }

    @Override
    public int RSACIPHER_private_decrypt(long rsaKeyId,
            int rsaPaddingId, int mdId, int mgf1Id, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.RSACIPHER_private_decrypt(osslContext.getId(), rsaKeyId, rsaPaddingId,
            mdId, mgf1Id, ciphertext, ciphertextOffset, ciphertextLen, plaintext, plaintextOffset, convertKey);
    }

    @Override
    public long DHKEY_generate(int numBits) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_generate(osslContext.getId(), numBits);
    }

    @Override
    public byte[] DHKEY_generateParameters(int numBits) {
        return NativeOpenSSLImplementation.DHKEY_generateParameters(osslContext.getId(), numBits);
    }

    @Override
    public long DHKEY_generate(byte[] dhParameters) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_generate(osslContext.getId(), dhParameters);
    }

    @Override
    public long DHKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_createPrivateKey(osslContext.getId(), privateKeyBytes);
    }

    @Override
    public long DHKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_createPublicKey(osslContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] DHKEY_getParameters(long dhKeyId) {
        return NativeOpenSSLImplementation.DHKEY_getParameters(osslContext.getId(), dhKeyId);
    }

    @Override
    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_getPrivateKeyBytes(osslContext.getId(), dhKeyId);
    }

    @Override
    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_getPublicKeyBytes(osslContext.getId(), dhKeyId);
    }

    @Override
    public long DHKEY_createPKey(long dhKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_createPKey(osslContext.getId(), dhKeyId);
    }

    @Override
    public byte[] DHKEY_computeDHSecret(long pubKeyId, long privKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DHKEY_computeDHSecret(osslContext.getId(), pubKeyId, privKeyId);
    }

    @Override
    public void DHKEY_delete(long dhKeyId) throws OpenSSLException {
        NativeOpenSSLImplementation.DHKEY_delete(osslContext.getId(), dhKeyId);
    }

    @Override
    public long RSAKEY_generate(int numBits, long e) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAKEY_generate(osslContext.getId(), numBits, e);
    }

    @Override
    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAKEY_createPrivateKey(osslContext.getId(), privateKeyBytes);
    }

    @Override
    public long RSAKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAKEY_createPublicKey(osslContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAKEY_getPrivateKeyBytes(osslContext.getId(), rsaKeyId);
    }

    @Override
    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAKEY_getPublicKeyBytes(osslContext.getId(), rsaKeyId);
    }

    @Override
    public int RSAKEY_size(long rsaKeyId) {
        return NativeOpenSSLImplementation.RSAKEY_size(osslContext.getId(), rsaKeyId);
    }

    @Override
    public void RSAKEY_delete(long rsaKeyId) {
        NativeOpenSSLImplementation.RSAKEY_delete(osslContext.getId(), rsaKeyId);
    }

    @Override
    public long DSAKEY_generate(int numBits) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_generate(osslContext.getId(), numBits);
    }

    @Override
    public byte[] DSAKEY_generateParameters(int numBits) {
        return NativeOpenSSLImplementation.DSAKEY_generateParameters(osslContext.getId(), numBits);
    }

    @Override
    public long DSAKEY_generate(byte[] dsaParameters) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_generate(osslContext.getId(), dsaParameters);
    }

    @Override
    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_createPrivateKey(osslContext.getId(), privateKeyBytes);
    }

    @Override
    public long DSAKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_createPublicKey(osslContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] DSAKEY_getParameters(long dsaKeyId) {
        return NativeOpenSSLImplementation.DSAKEY_getParameters(osslContext.getId(), dsaKeyId);
    }

    @Override
    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_getPrivateKeyBytes(osslContext.getId(), dsaKeyId);
    }

    @Override
    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_getPublicKeyBytes(osslContext.getId(), dsaKeyId);
    }

    @Override
    public long DSAKEY_createPKey(long dsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSAKEY_createPKey(osslContext.getId(), dsaKeyId);
    }

    @Override
    public void DSAKEY_delete(long dsaKeyId) throws OpenSSLException {
        NativeOpenSSLImplementation.DSAKEY_delete(osslContext.getId(), dsaKeyId);
    }

    @Override
    public void PKEY_delete(long pkeyId) throws OpenSSLException {
        NativeOpenSSLImplementation.PKEY_delete(osslContext.getId(), pkeyId);
    }

    @Override
    public long DIGEST_create(String digestAlgo) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_create(osslContext.getId(), digestAlgo);
    }

    @Override
    public long DIGEST_copy(long digestId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_copy(osslContext.getId(), digestId);
    }

    @Override
    public int DIGEST_update(long digestId, byte[] input, int offset, int length) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_update(osslContext.getId(), digestId, input, offset, length);
    }

    @Override
    public void DIGEST_updateFastJNI(long digestId, long inputBuffer, int length) throws OpenSSLException {
        NativeOpenSSLImplementation.DIGEST_updateFastJNI(osslContext.getId(), digestId, inputBuffer, length);
    }

    @Override
    public byte[] DIGEST_digest(long digestId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_digest(osslContext.getId(), digestId);
    }

    @Override
    public void DIGEST_digest_and_reset(long digestId, long outputBuffer, int length) throws OpenSSLException {
        NativeOpenSSLImplementation.DIGEST_digest_and_reset(osslContext.getId(), digestId, outputBuffer, length);
    }

    @Override
    public int DIGEST_digest_and_reset(long digestId, byte[] output) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_digest_and_reset(osslContext.getId(), digestId, output);
    }

    @Override
    public int DIGEST_size(long digestId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_size(osslContext.getId(), digestId);
    }

    @Override
    public void DIGEST_reset(long digestId) throws OpenSSLException {
        NativeOpenSSLImplementation.DIGEST_reset(osslContext.getId(), digestId);
    }

    @Override
    public void DIGEST_delete(long digestId) throws OpenSSLException {
        NativeOpenSSLImplementation.DIGEST_delete(osslContext.getId(), digestId);
    }

    @Override
    public int DIGEST_PKCS12KeyDeriveHelp(long digestId, byte[] input,
            int offset, int length, int iterationCount) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_PKCS12KeyDeriveHelp(osslContext.getId(),
                digestId, input, offset, length, iterationCount);
    }

    @Override
    public byte[] SIGNATURE_sign(long digestId, long pkeyId, boolean convert) throws OpenSSLException {
        return NativeOpenSSLImplementation.SIGNATURE_sign(osslContext.getId(), digestId, pkeyId, convert);
    }

    @Override
    public boolean SIGNATURE_verify(long digestId, long pkeyId, byte[] sigBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.SIGNATURE_verify(osslContext.getId(), digestId, pkeyId, sigBytes);
    }

    @Override
    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId, byte[] bytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.SIGNATUREEdDSA_signOneShot(osslContext.getId(), pkeyId, bytes);
    }

    @Override
    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId, byte[] sigBytes, byte[] oneShot) throws OpenSSLException {
        return NativeOpenSSLImplementation.SIGNATUREEdDSA_verifyOneShot(osslContext.getId(), pkeyId, sigBytes, oneShot);
    }

    @Override
    public int RSAPSS_signInit(long rsaPssId, long pkeyId, int saltlen, boolean convert) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAPSS_signInit(osslContext.getId(), rsaPssId, pkeyId, saltlen, convert);
    }

    @Override
    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId, int saltlen) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAPSS_verifyInit(osslContext.getId(), rsaPssId, pkeyId, saltlen);
    }

    @Override
    public int RSAPSS_getSigLen(long rsaPssId) {
        return NativeOpenSSLImplementation.RSAPSS_getSigLen(osslContext.getId(), rsaPssId);
    }

    @Override
    public void RSAPSS_signFinal(long rsaPssId, byte[] signature, int length) throws OpenSSLException {
        NativeOpenSSLImplementation.RSAPSS_signFinal(osslContext.getId(), rsaPssId, signature, length);
    }

    @Override
    public boolean RSAPSS_verifyFinal(long rsaPssId, byte[] sigBytes, int length) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAPSS_verifyFinal(osslContext.getId(), rsaPssId, sigBytes, length);
    }

    @Override
    public long RSAPSS_createContext(String digestAlgo, String mgf1SpecAlgo) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSAPSS_createContext(osslContext.getId(), digestAlgo, mgf1SpecAlgo);
    }

    @Override
    public void RSAPSS_releaseContext(long rsaPssId) throws OpenSSLException {
        NativeOpenSSLImplementation.RSAPSS_releaseContext(osslContext.getId(), rsaPssId);
    }

    @Override
    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input, int offset, int length) throws OpenSSLException {
        NativeOpenSSLImplementation.RSAPSS_digestUpdate(osslContext.getId(), rsaPssId, input, offset, length);
    }

    @Override
    public void RSAPSS_reset(long digestId) throws OpenSSLException {
        NativeOpenSSLImplementation.RSAPSS_reset(osslContext.getId(), digestId);
    }

    @Override
    public void RSAPSS_resetDigest(long rsaPssId) throws OpenSSLException {
        NativeOpenSSLImplementation.RSAPSS_resetDigest(osslContext.getId(), rsaPssId);
    }

    @Override
    public byte[] DSANONE_SIGNATURE_sign(byte[] digest, long dsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSANONE_SIGNATURE_sign(osslContext.getId(), digest, dsaKeyId);
    }

    @Override
    public boolean DSANONE_SIGNATURE_verify(byte[] digest, long dsaKeyId, byte[] sigBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.DSANONE_SIGNATURE_verify(osslContext.getId(), digest, dsaKeyId, sigBytes);
    }

    @Override
    public byte[] RSASSL_SIGNATURE_sign(byte[] digest, long rsaKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.RSASSL_SIGNATURE_sign(osslContext.getId(), digest, rsaKeyId);
    }

    @Override
    public boolean RSASSL_SIGNATURE_verify(byte[] digest, long rsaKeyId, byte[] sigBytes, boolean convert)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.RSASSL_SIGNATURE_verify(osslContext.getId(), digest, rsaKeyId, sigBytes, convert);
    }

    @Override
    public long HMAC_create(String digestAlgo) throws OpenSSLException {
        return NativeOpenSSLImplementation.HMAC_create(osslContext.getId(), digestAlgo);
    }

    @Override
    public int HMAC_update(long hmacId, byte[] key, int keyLength, byte[] input, int inputOffset, int inputLength,
            boolean needInit) throws OpenSSLException {
        return NativeOpenSSLImplementation.HMAC_update(osslContext.getId(), hmacId, key, keyLength,
            input, inputOffset, inputLength, needInit);
    }

    @Override
    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength, byte[] hmac, boolean needInit) throws OpenSSLException {
        return NativeOpenSSLImplementation.HMAC_doFinal(osslContext.getId(), hmacId, key, keyLength, hmac, needInit);
    }

    @Override
    public int HMAC_size(long hmacId) throws OpenSSLException {
        return NativeOpenSSLImplementation.HMAC_size(osslContext.getId(), hmacId);
    }

    @Override
    public void HMAC_delete(long hmacId) throws OpenSSLException {
        NativeOpenSSLImplementation.HMAC_delete(osslContext.getId(), hmacId);
    }

    @Override
    public long ECKEY_generate(int numBits) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_generate(osslContext.getId(), numBits);
    }

    @Override
    public long ECKEY_generate(String curveOid) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_generate(osslContext.getId(), curveOid);
    }

    @Override
    public long XECKEY_generate(int option, long bufferPtr) throws OpenSSLException {
        return NativeOpenSSLImplementation.XECKEY_generate(osslContext.getId(), option, bufferPtr);
    }

    @Override
    public byte[] ECKEY_generateParameters(int numBits) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_generateParameters(osslContext.getId(), numBits);
    }

    @Override
    public byte[] ECKEY_generateParameters(String curveOid) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_generateParameters(osslContext.getId(), curveOid);
    }

    @Override
    public long ECKEY_generate(byte[] ecParameters) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_generate(osslContext.getId(), ecParameters);
    }

    @Override
    public long ECKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_createPrivateKey(osslContext.getId(), privateKeyBytes);
    }

    @Override
    public long XECKEY_createPrivateKey(byte[] privateKeyBytes, long bufferPtr) throws OpenSSLException {
        return NativeOpenSSLImplementation.XECKEY_createPrivateKey(osslContext.getId(), privateKeyBytes, bufferPtr);
    }

    @Override
    public long ECKEY_createPublicKey(byte[] publicKeyBytes, byte[] parameterBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_createPublicKey(osslContext.getId(), publicKeyBytes, parameterBytes);
    }

    @Override
    public long XECKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        return NativeOpenSSLImplementation.XECKEY_createPublicKey(osslContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] ECKEY_getParameters(long ecKeyId) {
        return NativeOpenSSLImplementation.ECKEY_getParameters(osslContext.getId(), ecKeyId);
    }

    @Override
    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_getPrivateKeyBytes(osslContext.getId(), ecKeyId);
    }

    @Override
    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.XECKEY_getPrivateKeyBytes(osslContext.getId(), xecKeyId);
    }

    @Override
    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_getPublicKeyBytes(osslContext.getId(), ecKeyId);
    }

    @Override
    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.XECKEY_getPublicKeyBytes(osslContext.getId(), xecKeyId);
    }

    @Override
    public long ECKEY_createPKey(long ecKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_createPKey(osslContext.getId(), ecKeyId);
    }

    @Override
    public void ECKEY_delete(long ecKeyId) throws OpenSSLException {
        NativeOpenSSLImplementation.ECKEY_delete(osslContext.getId(), ecKeyId);
    }

    @Override
    public void XECKEY_delete(long xecKeyId) throws OpenSSLException {
        NativeOpenSSLImplementation.XECKEY_delete(osslContext.getId(), xecKeyId);
    }

    @Override
    public long XDHKeyAgreement_init(long privId) {
        return NativeOpenSSLImplementation.XDHKeyAgreement_init(osslContext.getId(), privId);
    }

    @Override
    public void XDHKeyAgreement_setPeer(long genCtx, long pubId) {
        NativeOpenSSLImplementation.XDHKeyAgreement_setPeer(osslContext.getId(), genCtx, pubId);
    }

    @Override
    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId, long privEcKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_computeECDHSecret(osslContext.getId(), pubEcKeyId, privEcKeyId);
    }

    @Override
    public byte[] XECKEY_computeECDHSecret(long genCtx, long pubEcKeyId, long privEcKeyId)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.XECKEY_computeECDHSecret(osslContext.getId(), genCtx, pubEcKeyId, privEcKeyId);
    }

    @Override
    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes, int digestBytesLen, long ecPrivateKeyId)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_signDatawithECDSA(osslContext.getId(), digestBytes, digestBytesLen, ecPrivateKeyId);
    }

    @Override
    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes, int digestBytesLen, byte[] sigBytes, int sigBytesLen,
            long ecPublicKeyId) throws OpenSSLException {
        return NativeOpenSSLImplementation.ECKEY_verifyDatawithECDSA(osslContext.getId(), digestBytes, digestBytesLen,
            sigBytes, sigBytesLen, ecPublicKeyId);
    }

    @Override
    public long HKDF_create(String digestAlgo) throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_create(osslContext.getId(), digestAlgo);
    }

    @Override
    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_extract(osslContext.getId(), hkdfId, saltBytes, saltLen, inKey, inKeyLen);
    }

    @Override
    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes, long prkBytesLen, byte[] info, long infoLen, long okmLen)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_expand(osslContext.getId(), hkdfId, prkBytes, prkBytesLen, info, infoLen, okmLen);
    }

    @Override
    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen, byte[] info,
            long infoLen, long okmLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_derive(osslContext.getId(), hkdfId,
            saltBytes, saltLen, inKey, inKeyLen, info, infoLen, okmLen);
    }

    @Override
    public void HKDF_delete(long hkdfId) throws OpenSSLException {
        NativeOpenSSLImplementation.HKDF_delete(osslContext.getId(), hkdfId);
    }

    @Override
    public int HKDF_size(long hkdfId) throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_size(osslContext.getId(), hkdfId);
    }

    @Override
    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt, int iterations, int keyLength)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.PBKDF2_derive(osslContext.getId(), hashAlgorithm, password, salt, iterations, keyLength);
    }

    @Override
    public long MLKEY_generate(String cipherName)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.MLKEY_generate(osslContext.getId(), cipherName);
    }

    @Override
    public long MLKEY_createPrivateKey(String cipherName, byte[] privateKeyBytes)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.MLKEY_createPrivateKey(osslContext.getId(), cipherName, privateKeyBytes);
    }

    @Override
    public long MLKEY_createPublicKey(String cipherName, byte[] publicKeyBytes)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.MLKEY_createPublicKey(osslContext.getId(), cipherName, publicKeyBytes);
    }

    @Override
    public byte[] MLKEY_getPrivateKeyBytes(long mlkeyId)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.MLKEY_getPrivateKeyBytes(osslContext.getId(), mlkeyId);
    }

    @Override
    public byte[] MLKEY_getPublicKeyBytes(long mlkeyId)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.MLKEY_getPublicKeyBytes(osslContext.getId(), mlkeyId);
    }

    @Override
    public void MLKEY_delete(long mlkeyId) {
        NativeOpenSSLImplementation.MLKEY_delete(osslContext.getId(), mlkeyId);
    }

    @Override
    public void KEM_encapsulate(long pKeyId, byte[] wrappedKey, byte[] randomKey)
            throws OpenSSLException {
        NativeOpenSSLImplementation.KEM_encapsulate(osslContext.getId(), pKeyId, wrappedKey, randomKey);
    }

    @Override
    public byte[] KEM_decapsulate(long pKeyId, byte[] wrappedKey)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.KEM_decapsulate(osslContext.getId(), pKeyId, wrappedKey);
    }

    @Override
    public byte[] PQC_SIGNATURE_sign(long pKeyId, byte[] data)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.PQC_SIGNATURE_sign(osslContext.getId(), pKeyId, data);
    }

    @Override
    public boolean PQC_SIGNATURE_verify(long pKeyId, byte[] sigBytes, byte[] data)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.PQC_SIGNATURE_verify(osslContext.getId(), pKeyId, sigBytes, data);
    }
}

