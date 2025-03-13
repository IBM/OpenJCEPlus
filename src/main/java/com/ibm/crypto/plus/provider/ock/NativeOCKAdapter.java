/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.base.NativeInterface;
import com.ibm.crypto.plus.provider.base.OCKContext;
import com.ibm.crypto.plus.provider.base.OCKException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.security.ProviderException;
import sun.security.util.Debug;

public abstract class NativeOCKAdapter implements NativeInterface {
    // These code values must match those defined in Context.h.
    //
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OCK_INSTALL_PATH = 1;
    private static final int VALUE_OCK_VERSION = 2;

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    static final String unobtainedValue = new String();

    // whether to validate OCK was loaded from JRE location
    private static final boolean validateOCKLocation = true;

    // whether to validate OCK version of load library matches version in ICCSIG.txt
    private static final boolean validateOCKVersion = false;

    private OCKContext ockContext = null;
    private boolean ockInitialized = false;
    private boolean useFIPSMode;

    private String ockVersion = unobtainedValue;
    private String ockInstallPath = unobtainedValue;

    // The following is a special String instance to indicate that a
    // value has not yet been obtained.  We do this because some values
    // may be null and we only want to query the value one time.
    //
    private static String libraryBuildDate = unobtainedValue;

    NativeOCKAdapter(boolean useFIPSMode) {
        this.useFIPSMode = useFIPSMode;
        initializeContext();
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
            long ockContextId =  NativeOCKImplementation.initializeOCK(this.useFIPSMode);
            this.ockContext = OCKContext.createContext(ockContextId, this.useFIPSMode);
            getLibraryBuildDate();

            if (validateOCKLocation) {
                validateLibraryLocation();
            }

            if (validateOCKVersion) {
                validateLibraryVersion();
            }

            this.ockInitialized = true;
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

    @Override
    public String getLibraryVersion() throws OCKException {
        if (ockVersion == unobtainedValue) {
            obtainOCKVersion();
        }
        return ockVersion;
    }

    @Override
    public String getLibraryInstallPath() throws OCKException {
        if (ockInstallPath == unobtainedValue) {
            obtainOCKInstallPath();
        }
        return ockInstallPath;
    }


    private synchronized void obtainOCKVersion() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (ockVersion == unobtainedValue) {
            ockVersion = CTX_getValue(VALUE_OCK_VERSION);
        }
    }

    private synchronized void obtainOCKInstallPath() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (ockInstallPath == unobtainedValue) {
            ockInstallPath = CTX_getValue(VALUE_OCK_INSTALL_PATH);
        }
    }

    static public ProviderException providerException(String message, Throwable ockException) {
        ProviderException providerException = new ProviderException(message, ockException);
        setOCKExceptionCause(providerException, ockException);
        return providerException;
    }

    static public void setOCKExceptionCause(Exception exception, Throwable ockException) {
        if (debug != null) {
            exception.initCause(ockException);
        }
    }

    @Override
    public void validateLibraryLocation() throws ProviderException, OCKException {
        if (NativeOCKImplementation.requirePreloadOCK == false) {
            // If we are not requiring OCK to be pre-loaded, then it does not need to be
            // loaded from the JRE location
            //
            return;
        }

        try {
            // Check to make sure that the OCK install path is within the JRE
            //
            String ockLoadPath = new File(NativeOCKImplementation.getOCKLoadPath()).getCanonicalPath();
            String ockInstallPath = new File(getLibraryInstallPath()).getCanonicalPath();

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

    @Override
    public void validateLibraryVersion() throws ProviderException, OCKException {
        if (NativeOCKImplementation.requirePreloadOCK == false) {
            // If we are not requiring OCK to be pre-loaded, then it does not need to be
            // a specific version
            //
            return;
        }

        String expectedVersion = getExpectedLibraryVersion();
        String actualVersion = getLibraryVersion();

        if (expectedVersion == null) {
            throw new ProviderException(
                    "Could not not determine expected version of dependent library");
        } else if (expectedVersion.equals(actualVersion) == false) {
            throw new ProviderException("Expected depdendent library version " + expectedVersion
                    + ", got " + actualVersion);
        }
    }

    private String getExpectedLibraryVersion() {
        String ockLoadPath = NativeOCKImplementation.getOCKLoadPath();
        String ockSigFileName;
        if (this.useFIPSMode) {
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

    @Override
    public String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeOCKImplementation.getLibraryBuildDate();;
        }
        return libraryBuildDate;
    }

    @Override
    public long initializeOCK(boolean isFIPS) throws OCKException {
        return NativeOCKImplementation.initializeOCK(isFIPS);
    }

    @Override
    public String CTX_getValue(int valueId) throws OCKException {
        return NativeOCKImplementation.CTX_getValue(ockContext.getId(), valueId);
    }

    @Override
    public long getByteBufferPointer(ByteBuffer b) {
        return NativeOCKImplementation.getByteBufferPointer(b);
    }

    @Override
    public void RAND_nextBytes(byte[] buffer) throws OCKException {
        NativeOCKImplementation.RAND_nextBytes(ockContext.getId(), buffer);
    }

    @Override
    public void RAND_setSeed(byte[] seed) throws OCKException {
        NativeOCKImplementation.RAND_setSeed(ockContext.getId(), seed);
    }

    @Override
    public void RAND_generateSeed(byte[] seed) throws OCKException {
        NativeOCKImplementation.RAND_generateSeed(ockContext.getId(), seed);
    }

    @Override
    public long EXTRAND_create(String algName) throws OCKException {
        return NativeOCKImplementation.EXTRAND_create(ockContext.getId(), algName);
    }

    @Override
    public void EXTRAND_nextBytes(long ockPRNGContextId, byte[] buffer) throws OCKException {
        NativeOCKImplementation.EXTRAND_nextBytes(ockContext.getId(), ockPRNGContextId, buffer);
    }

    @Override
    public void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed) throws OCKException {
        NativeOCKImplementation.EXTRAND_setSeed(ockContext.getId(), ockPRNGContextId, seed);
    }

    @Override
    public void EXTRAND_delete(long ockPRNGContextId) throws OCKException {
        NativeOCKImplementation.EXTRAND_delete(ockContext.getId(), ockPRNGContextId);
    }

    @Override
    public long CIPHER_create(String cipher) throws OCKException {
        return NativeOCKImplementation.CIPHER_create(ockContext.getId(), cipher);
    }

    @Override
    public void CIPHER_init(long ockCipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) throws OCKException {
        NativeOCKImplementation.CIPHER_init(ockContext.getId(), ockCipherId, isEncrypt, paddingId, key, iv);
    }

    @Override
    public void CIPHER_clean(long ockCipherId) throws OCKException {
        NativeOCKImplementation.CIPHER_clean(ockContext.getId(), ockCipherId);
    }

    @Override
    public void CIPHER_setPadding(long ockCipherId, int paddingId) throws OCKException {
        NativeOCKImplementation.CIPHER_setPadding(ockContext.getId(), ockCipherId, paddingId);
    }

    @Override
    public int CIPHER_getBlockSize(long ockCipherId) {
        return NativeOCKImplementation.CIPHER_getBlockSize(ockContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_getKeyLength(long ockCipherId) {
        return NativeOCKImplementation.CIPHER_getKeyLength(ockContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_getIVLength(long ockCipherId) {
        return NativeOCKImplementation.CIPHER_getIVLength(ockContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_getOID(long ockCipherId) {
        return NativeOCKImplementation.CIPHER_getOID(ockContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_encryptUpdate(long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OCKException {
        return NativeOCKImplementation.CIPHER_encryptUpdate(ockContext.getId(), ockCipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptUpdate(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OCKException {
        return NativeOCKImplementation.CIPHER_decryptUpdate(ockContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public int CIPHER_encryptFinal(long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OCKException {
        return NativeOCKImplementation.CIPHER_encryptFinal(ockContext.getId(), ockCipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptFinal(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OCKException {
        return NativeOCKImplementation.CIPHER_decryptFinal(ockContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public long checkHardwareSupport() {
        return NativeOCKImplementation.checkHardwareSupport(ockContext.getId());
    }

    @Override
    public void CIPHER_delete(long ockCipherId) throws OCKException {
        NativeOCKImplementation.CIPHER_delete(ockContext.getId(), ockCipherId);
    }

    @Override
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type)
            throws OCKException {
        return NativeOCKImplementation.CIPHER_KeyWraporUnwrap(ockContext.getId(), key, KEK, type);
    }

    @Override
    public int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer,
            int inputLength, int mode) {
        return NativeOCKImplementation.z_kmc_native(input, inputOffset, output, outputOffset, paramPointer, inputLength, mode);
    }

    @Override
    public long POLY1305CIPHER_create(String cipher) throws OCKException {
        return NativeOCKImplementation.POLY1305CIPHER_create(ockContext.getId(), cipher);
    }

    @Override
    public void POLY1305CIPHER_init(long ockCipherId, int isEncrypt, byte[] key, byte[] iv) throws OCKException {
        NativeOCKImplementation.POLY1305CIPHER_init(ockContext.getId(), ockCipherId, isEncrypt, key, iv);
    }

    @Override
    public void POLY1305CIPHER_clean(long ockCipherId) throws OCKException {
        NativeOCKImplementation.POLY1305CIPHER_clean(ockContext.getId(), ockCipherId);
    }

    @Override
    public void POLY1305CIPHER_setPadding(long ockCipherId, int paddingId) throws OCKException {
        NativeOCKImplementation.POLY1305CIPHER_setPadding(ockContext.getId(), ockCipherId, paddingId);
    }

    @Override
    public int POLY1305CIPHER_getBlockSize(long ockCipherId) {
        return NativeOCKImplementation.POLY1305CIPHER_getBlockSize(ockContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getKeyLength(long ockCipherId) {
        return NativeOCKImplementation.POLY1305CIPHER_getKeyLength(ockContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getIVLength(long ockCipherId) {
        return NativeOCKImplementation.POLY1305CIPHER_getIVLength(ockContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getOID(long ockCipherId) {
        return NativeOCKImplementation.POLY1305CIPHER_getOID(ockContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_encryptUpdate(long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OCKException {
        return NativeOCKImplementation.POLY1305CIPHER_encryptUpdate(ockContext.getId(), ockCipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int POLY1305CIPHER_decryptUpdate(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OCKException {
        return NativeOCKImplementation.POLY1305CIPHER_decryptUpdate(ockContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int POLY1305CIPHER_encryptFinal(long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] tag) throws OCKException {
        return NativeOCKImplementation.POLY1305CIPHER_encryptFinal(ockContext.getId(), ockCipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, tag);
    }

    @Override
    public int POLY1305CIPHER_decryptFinal(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] tag) throws OCKException {
        return NativeOCKImplementation.POLY1305CIPHER_decryptFinal(ockContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, tag);
    }

    @Override
    public void POLY1305CIPHER_delete(long ockCipherId) throws OCKException {
        NativeOCKImplementation.POLY1305CIPHER_delete(ockContext.getId(), ockCipherId);
    }

    @Override
    public long do_GCM_checkHardwareGCMSupport() {
        return NativeOCKImplementation.do_GCM_checkHardwareGCMSupport(ockContext.getId());
    }

    @Override
    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        return NativeOCKImplementation.do_GCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen,
            inOffset, inLen, ciphertextOffset, aadLen, tagLen, parameterBuffer,
            input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset,
            int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException {
        return NativeOCKImplementation.do_GCM_encryptFastJNI(ockContext.getId(), gcmCtx, keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        return NativeOCKImplementation.do_GCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen,
            int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OCKException {
        return NativeOCKImplementation.do_GCM_decryptFastJNI(ockContext.getId(), gcmCtx, keyLen, ivLen,
            ciphertextOffset, ciphertextLen, plainOffset, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset,
            int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OCKException {
        return NativeOCKImplementation.do_GCM_encrypt(ockContext.getId(), gcmCtx, key, keyLen, iv, ivLen,
            input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tag, tagLen);
    }

    @Override
    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext,
            int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OCKException {
        return NativeOCKImplementation.do_GCM_decrypt(ockContext.getId(), gcmCtx, key, keyLen, iv, ivLen,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, aad, aadLen, tagLen);
    }

    @Override
    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag,
            int tagLen) throws OCKException {
        return NativeOCKImplementation.do_GCM_FinalForUpdateEncrypt(ockContext.getId(), gcmCtx, key, keyLen, iv, ivLen,
            input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tag, tagLen);
    }

    @Override
    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OCKException {
        return NativeOCKImplementation.do_GCM_FinalForUpdateDecrypt(ockContext.getId(), gcmCtx,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, plaintextlen, aad, aadLen, tagLen);
    }

    @Override
    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset) throws OCKException {
        return NativeOCKImplementation.do_GCM_UpdForUpdateEncrypt(ockContext.getId(), gcmCtx,
            input, inOffset, inLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OCKException {
        return NativeOCKImplementation.do_GCM_UpdForUpdateDecrypt(ockContext.getId(), gcmCtx,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OCKException {
        return NativeOCKImplementation.do_GCM_InitForUpdateEncrypt(ockContext.getId(), gcmCtx,
            key, keyLen, iv, ivLen, aad, aadLen);
    }

    @Override
    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OCKException {
        return NativeOCKImplementation.do_GCM_InitForUpdateDecrypt(ockContext.getId(), gcmCtx,
            key, keyLen, iv, ivLen, aad, aadLen);
    }

    @Override
    public void do_GCM_delete() throws OCKException {
        NativeOCKImplementation.do_GCM_delete(ockContext.getId());
    }

    @Override
    public void free_GCM_ctx(long gcmContextId) throws OCKException {
        NativeOCKImplementation.free_GCM_ctx(ockContext.getId(), gcmContextId);
    }

    @Override
    public long create_GCM_context() throws OCKException {
        return NativeOCKImplementation.create_GCM_context(ockContext.getId());
    }

    @Override
    public long do_CCM_checkHardwareCCMSupport() {
        return NativeOCKImplementation.do_CCM_checkHardwareCCMSupport(ockContext.getId());
    }

    @Override
    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        return NativeOCKImplementation.do_CCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_CCM_encryptFastJNI(int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException {
        return NativeOCKImplementation.do_CCM_encryptFastJNI(ockContext.getId(), keyLen, ivLen, inLen,
            ciphertextLen, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        return NativeOCKImplementation.do_CCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_CCM_decryptFastJNI(int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException {
        return NativeOCKImplementation.do_CCM_decryptFastJNI(ockContext.getId(), keyLen, ivLen, ciphertextLen,
            plaintextLen, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input,
            int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) throws OCKException {
        return NativeOCKImplementation.do_CCM_encrypt(ockContext.getId(), iv, ivLen, key, keyLen,
            aad, aadLen, input, inLen, ciphertext, ciphertextLen, tagLen);
    }

    @Override
    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] ciphertext,
            int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen) throws OCKException {
        return NativeOCKImplementation.do_CCM_decrypt(ockContext.getId(), iv, ivLen, key, keyLen,
            aad, aadLen, ciphertext, ciphertextLength, plaintext, plaintextLength, tagLen);
    }

    @Override
    public void do_CCM_delete() throws OCKException {
        NativeOCKImplementation.do_CCM_delete(ockContext.getId());
    }

    @Override
    public int RSACIPHER_public_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws OCKException {
        return NativeOCKImplementation.RSACIPHER_public_encrypt(ockContext.getId(), rsaKeyId, rsaPaddingId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int RSACIPHER_private_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OCKException {
        return NativeOCKImplementation.RSACIPHER_private_encrypt(ockContext.getId(), rsaKeyId, rsaPaddingId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, convertKey);
    }

    @Override
    public int RSACIPHER_public_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset) throws OCKException {
        return NativeOCKImplementation.RSACIPHER_public_decrypt(ockContext.getId(), rsaKeyId, rsaPaddingId,
            ciphertext, ciphertextOffset, ciphertextLen, plaintext, plaintextOffset);
    }

    @Override
    public int RSACIPHER_private_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey) throws OCKException {
        return NativeOCKImplementation.RSACIPHER_private_decrypt(ockContext.getId(), rsaKeyId, rsaPaddingId,
            ciphertext, ciphertextOffset, ciphertextLen, plaintext, plaintextOffset, convertKey);
    }

    @Override
    public long DHKEY_generate(int numBits) throws OCKException {
        return NativeOCKImplementation.DHKEY_generate(ockContext.getId(), numBits);
    }

    @Override
    public byte[] DHKEY_generateParameters(int numBits) {
        return NativeOCKImplementation.DHKEY_generateParameters(ockContext.getId(), numBits);
    }

    @Override
    public long DHKEY_generate(byte[] dhParameters) throws OCKException {
        return NativeOCKImplementation.DHKEY_generate(ockContext.getId(), dhParameters);
    }

    @Override
    public long DHKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        return NativeOCKImplementation.DHKEY_createPrivateKey(ockContext.getId(), privateKeyBytes);
    }

    @Override
    public long DHKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        return NativeOCKImplementation.DHKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] DHKEY_getParameters(long dhKeyId) {
        return NativeOCKImplementation.DHKEY_getParameters(ockContext.getId(), dhKeyId);
    }

    @Override
    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId) throws OCKException {
        return NativeOCKImplementation.DHKEY_getPrivateKeyBytes(ockContext.getId(), dhKeyId);
    }

    @Override
    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId) throws OCKException {
        return NativeOCKImplementation.DHKEY_getPublicKeyBytes(ockContext.getId(), dhKeyId);
    }

    @Override
    public long DHKEY_createPKey(long dhKeyId) throws OCKException {
        return NativeOCKImplementation.DHKEY_createPKey(ockContext.getId(), dhKeyId);
    }

    @Override
    public byte[] DHKEY_computeDHSecret(long pubKeyId, long privKeyId) throws OCKException {
        return NativeOCKImplementation.DHKEY_computeDHSecret(ockContext.getId(), pubKeyId, privKeyId);
    }

    @Override
    public void DHKEY_delete(long dhKeyId) throws OCKException {
        NativeOCKImplementation.DHKEY_delete(ockContext.getId(), dhKeyId);
    }

    @Override
    public long RSAKEY_generate(int numBits, long e) throws OCKException {
        return NativeOCKImplementation.RSAKEY_generate(ockContext.getId(), numBits, e);
    }

    @Override
    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        return NativeOCKImplementation.RSAKEY_createPrivateKey(ockContext.getId(), privateKeyBytes);
    }

    @Override
    public long RSAKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        return NativeOCKImplementation.RSAKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId) throws OCKException {
        return NativeOCKImplementation.RSAKEY_getPrivateKeyBytes(ockContext.getId(), rsaKeyId);
    }

    @Override
    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId) throws OCKException {
        return NativeOCKImplementation.RSAKEY_getPublicKeyBytes(ockContext.getId(), rsaKeyId);
    }

    @Override
    public long RSAKEY_createPKey(long rsaKeyId) throws OCKException {
        return NativeOCKImplementation.RSAKEY_createPKey(ockContext.getId(), rsaKeyId);
    }

    @Override
    public int RSAKEY_size(long rsaKeyId) {
        return NativeOCKImplementation.RSAKEY_size(ockContext.getId(), rsaKeyId);
    }

    @Override
    public void RSAKEY_delete(long rsaKeyId) {
        NativeOCKImplementation.RSAKEY_delete(ockContext.getId(), rsaKeyId);
    }

    @Override
    public long DSAKEY_generate(int numBits) throws OCKException {
        return NativeOCKImplementation.DSAKEY_generate(ockContext.getId(), numBits);
    }

    @Override
    public byte[] DSAKEY_generateParameters(int numBits) {
        return NativeOCKImplementation.DSAKEY_generateParameters(ockContext.getId(), numBits);
    }

    @Override
    public long DSAKEY_generate(byte[] dsaParameters) throws OCKException {
        return NativeOCKImplementation.DSAKEY_generate(ockContext.getId(), dsaParameters);
    }

    @Override
    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        return NativeOCKImplementation.DSAKEY_createPrivateKey(ockContext.getId(), privateKeyBytes);
    }

    @Override
    public long DSAKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        return NativeOCKImplementation.DSAKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] DSAKEY_getParameters(long dsaKeyId) {
        return NativeOCKImplementation.DSAKEY_getParameters(ockContext.getId(), dsaKeyId);
    }

    @Override
    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId) throws OCKException {
        return NativeOCKImplementation.DSAKEY_getPrivateKeyBytes(ockContext.getId(), dsaKeyId);
    }

    @Override
    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId) throws OCKException {
        return NativeOCKImplementation.DSAKEY_getPublicKeyBytes(ockContext.getId(), dsaKeyId);
    }

    @Override
    public long DSAKEY_createPKey(long dsaKeyId) throws OCKException {
        return NativeOCKImplementation.DSAKEY_createPKey(ockContext.getId(), dsaKeyId);
    }

    @Override
    public void DSAKEY_delete(long dsaKeyId) throws OCKException {
        NativeOCKImplementation.DSAKEY_delete(ockContext.getId(), dsaKeyId);
    }

    @Override
    public void PKEY_delete(long pkeyId) throws OCKException {
        NativeOCKImplementation.PKEY_delete(ockContext.getId(), pkeyId);
    }

    @Override
    public long DIGEST_create(String digestAlgo) throws OCKException {
        return NativeOCKImplementation.DIGEST_create(ockContext.getId(), digestAlgo);
    }

    @Override
    public long DIGEST_copy(long digestId) throws OCKException {
        return NativeOCKImplementation.DIGEST_copy(ockContext.getId(), digestId);
    }

    @Override
    public int DIGEST_update(long digestId, byte[] input, int offset, int length) throws OCKException {
        return NativeOCKImplementation.DIGEST_update(ockContext.getId(), digestId, input, offset, length);
    }

    @Override
    public void DIGEST_updateFastJNI(long digestId, long inputBuffer, int length) throws OCKException {
        NativeOCKImplementation.DIGEST_updateFastJNI(ockContext.getId(), digestId, inputBuffer, length);
    }

    @Override
    public byte[] DIGEST_digest(long digestId) throws OCKException {
        return NativeOCKImplementation.DIGEST_digest(ockContext.getId(), digestId);
    }

    @Override
    public void DIGEST_digest_and_reset(long digestId, long outputBuffer, int length) throws OCKException {
        NativeOCKImplementation.DIGEST_digest_and_reset(ockContext.getId(), digestId, outputBuffer, length);
    }

    @Override
    public int DIGEST_digest_and_reset(long digestId, byte[] output) throws OCKException {
        return NativeOCKImplementation.DIGEST_digest_and_reset(ockContext.getId(), digestId, output);
    }

    @Override
    public int DIGEST_size(long digestId) throws OCKException {
        return NativeOCKImplementation.DIGEST_size(ockContext.getId(), digestId);
    }

    @Override
    public void DIGEST_reset(long digestId) throws OCKException {
        NativeOCKImplementation.DIGEST_reset(ockContext.getId(), digestId);
    }

    @Override
    public void DIGEST_delete(long digestId) throws OCKException {
        NativeOCKImplementation.DIGEST_delete(ockContext.getId(), digestId);
    }

    @Override
    public byte[] SIGNATURE_sign(long digestId, long pkeyId, boolean convert) throws OCKException {
        return NativeOCKImplementation.SIGNATURE_sign(ockContext.getId(), digestId, pkeyId, convert);
    }

    @Override
    public boolean SIGNATURE_verify(long digestId, long pkeyId, byte[] sigBytes) throws OCKException {
        return NativeOCKImplementation.SIGNATURE_verify(ockContext.getId(), digestId, pkeyId, sigBytes);
    }

    @Override
    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId, byte[] bytes) throws OCKException {
        return NativeOCKImplementation.SIGNATUREEdDSA_signOneShot(ockContext.getId(), pkeyId, bytes);
    }

    @Override
    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId, byte[] sigBytes, byte[] oneShot) throws OCKException {
        return NativeOCKImplementation.SIGNATUREEdDSA_verifyOneShot(ockContext.getId(), pkeyId, sigBytes, oneShot);
    }

    @Override
    public int RSAPSS_signInit(long rsaPssId, long pkeyId, int saltlen, boolean convert) throws OCKException {
        return NativeOCKImplementation.RSAPSS_signInit(ockContext.getId(), rsaPssId, pkeyId, saltlen, convert);
    }

    @Override
    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId, int saltlen) throws OCKException {
        return NativeOCKImplementation.RSAPSS_verifyInit(ockContext.getId(), rsaPssId, pkeyId, saltlen);
    }

    @Override
    public int RSAPSS_getSigLen(long rsaPssId) {
        return NativeOCKImplementation.RSAPSS_getSigLen(ockContext.getId(), rsaPssId);
    }

    @Override
    public void RSAPSS_signFinal(long rsaPssId, byte[] signature, int length) throws OCKException {
        NativeOCKImplementation.RSAPSS_signFinal(ockContext.getId(), rsaPssId, signature, length);
    }

    @Override
    public boolean RSAPSS_verifyFinal(long rsaPssId, byte[] sigBytes, int length) throws OCKException {
        return NativeOCKImplementation.RSAPSS_verifyFinal(ockContext.getId(), rsaPssId, sigBytes, length);
    }

    @Override
    public long RSAPSS_createContext(String digestAlgo, String mgf1SpecAlgo) throws OCKException {
        return NativeOCKImplementation.RSAPSS_createContext(ockContext.getId(), digestAlgo, mgf1SpecAlgo);
    }

    @Override
    public void RSAPSS_releaseContext(long rsaPssId) throws OCKException {
        NativeOCKImplementation.RSAPSS_releaseContext(ockContext.getId(), rsaPssId);
    }

    @Override
    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input, int offset, int length) throws OCKException {
        NativeOCKImplementation.RSAPSS_digestUpdate(ockContext.getId(), rsaPssId, input, offset, length);
    }

    @Override
    public void RSAPSS_reset(long digestId) throws OCKException {
        NativeOCKImplementation.RSAPSS_reset(ockContext.getId(), digestId);
    }

    @Override
    public void RSAPSS_resetDigest(long rsaPssId) throws OCKException {
        NativeOCKImplementation.RSAPSS_resetDigest(ockContext.getId(), rsaPssId);
    }

    @Override
    public byte[] DSANONE_SIGNATURE_sign(byte[] digest, long dsaKeyId) throws OCKException {
        return NativeOCKImplementation.DSANONE_SIGNATURE_sign(ockContext.getId(), digest, dsaKeyId);
    }

    @Override
    public boolean DSANONE_SIGNATURE_verify(byte[] digest, long dsaKeyId, byte[] sigBytes) throws OCKException {
        return NativeOCKImplementation.DSANONE_SIGNATURE_verify(ockContext.getId(), digest, dsaKeyId, sigBytes);
    }

    @Override
    public byte[] RSASSL_SIGNATURE_sign(byte[] digest, long rsaKeyId) throws OCKException {
        return NativeOCKImplementation.RSASSL_SIGNATURE_sign(ockContext.getId(), digest, rsaKeyId);
    }

    @Override
    public boolean RSASSL_SIGNATURE_verify(byte[] digest, long rsaKeyId, byte[] sigBytes, boolean convert)
            throws OCKException {
        return NativeOCKImplementation.RSASSL_SIGNATURE_verify(ockContext.getId(), digest, rsaKeyId, sigBytes, convert);
    }

    @Override
    public long HMAC_create(String digestAlgo) throws OCKException {
        return NativeOCKImplementation.HMAC_create(ockContext.getId(), digestAlgo);
    }

    @Override
    public int HMAC_update(long hmacId, byte[] key, int keyLength, byte[] input, int inputOffset, int inputLength,
            boolean needInit) throws OCKException {
        return NativeOCKImplementation.HMAC_update(ockContext.getId(), hmacId, key, keyLength,
            input, inputOffset, inputLength, needInit);
    }

    @Override
    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength, byte[] hmac, boolean needInit) throws OCKException {
        return NativeOCKImplementation.HMAC_doFinal(ockContext.getId(), hmacId, key, keyLength, hmac, needInit);
    }

    @Override
    public int HMAC_size(long hmacId) throws OCKException {
        return NativeOCKImplementation.HMAC_size(ockContext.getId(), hmacId);
    }

    @Override
    public void HMAC_delete(long hmacId) throws OCKException {
        NativeOCKImplementation.HMAC_delete(ockContext.getId(), hmacId);
    }

    @Override
    public long ECKEY_generate(int numBits) throws OCKException {
        return NativeOCKImplementation.ECKEY_generate(ockContext.getId(), numBits);
    }

    @Override
    public long ECKEY_generate(String curveOid) throws OCKException {
        return NativeOCKImplementation.ECKEY_generate(ockContext.getId(), curveOid);
    }

    @Override
    public long XECKEY_generate(int option, long bufferPtr) throws OCKException {
        return NativeOCKImplementation.XECKEY_generate(ockContext.getId(), option, bufferPtr);
    }

    @Override
    public byte[] ECKEY_generateParameters(int numBits) throws OCKException {
        return NativeOCKImplementation.ECKEY_generateParameters(ockContext.getId(), numBits);
    }

    @Override
    public byte[] ECKEY_generateParameters(String curveOid) throws OCKException {
        return NativeOCKImplementation.ECKEY_generateParameters(ockContext.getId(), curveOid);
    }

    @Override
    public long ECKEY_generate(byte[] ecParameters) throws OCKException {
        return NativeOCKImplementation.ECKEY_generate(ockContext.getId(), ecParameters);
    }

    @Override
    public long ECKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        return NativeOCKImplementation.ECKEY_createPrivateKey(ockContext.getId(), privateKeyBytes);
    }

    @Override
    public long XECKEY_createPrivateKey(byte[] privateKeyBytes, long bufferPtr) throws OCKException {
        return NativeOCKImplementation.XECKEY_createPrivateKey(ockContext.getId(), privateKeyBytes, bufferPtr);
    }

    @Override
    public long ECKEY_createPublicKey(byte[] publicKeyBytes, byte[] parameterBytes) throws OCKException {
        return NativeOCKImplementation.ECKEY_createPublicKey(ockContext.getId(), publicKeyBytes, parameterBytes);
    }

    @Override
    public long XECKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        return NativeOCKImplementation.XECKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
    }

    @Override
    public byte[] ECKEY_getParameters(long ecKeyId) {
        return NativeOCKImplementation.ECKEY_getParameters(ockContext.getId(), ecKeyId);
    }

    @Override
    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId) throws OCKException {
        return NativeOCKImplementation.ECKEY_getPrivateKeyBytes(ockContext.getId(), ecKeyId);
    }

    @Override
    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId) throws OCKException {
        return NativeOCKImplementation.XECKEY_getPrivateKeyBytes(ockContext.getId(), xecKeyId);
    }

    @Override
    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId) throws OCKException {
        return NativeOCKImplementation.ECKEY_getPublicKeyBytes(ockContext.getId(), ecKeyId);
    }

    @Override
    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId) throws OCKException {
        return NativeOCKImplementation.XECKEY_getPublicKeyBytes(ockContext.getId(), xecKeyId);
    }

    @Override
    public long ECKEY_createPKey(long ecKeyId) throws OCKException {
        return NativeOCKImplementation.ECKEY_createPKey(ockContext.getId(), ecKeyId);
    }

    @Override
    public void ECKEY_delete(long ecKeyId) throws OCKException {
        NativeOCKImplementation.ECKEY_delete(ockContext.getId(), ecKeyId);
    }

    @Override
    public void XECKEY_delete(long xecKeyId) throws OCKException {
        NativeOCKImplementation.XECKEY_delete(ockContext.getId(), xecKeyId);
    }

    @Override
    public long XDHKeyAgreement_init(long privId) {
        return NativeOCKImplementation.XDHKeyAgreement_init(ockContext.getId(), privId);
    }

    @Override
    public void XDHKeyAgreement_setPeer(long genCtx, long pubId) {
        NativeOCKImplementation.XDHKeyAgreement_setPeer(ockContext.getId(), genCtx, pubId);
    }

    @Override
    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId, long privEcKeyId) throws OCKException {
        return NativeOCKImplementation.ECKEY_computeECDHSecret(ockContext.getId(), pubEcKeyId, privEcKeyId);
    }

    @Override
    public byte[] XECKEY_computeECDHSecret(long genCtx, long pubEcKeyId, long privEcKeyId, int secrectBufferSize)
            throws OCKException {
        return NativeOCKImplementation.XECKEY_computeECDHSecret(ockContext.getId(), genCtx, pubEcKeyId, privEcKeyId, secrectBufferSize);
    }

    @Override
    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes, int digestBytesLen, long ecPrivateKeyId)
            throws OCKException {
        return NativeOCKImplementation.ECKEY_signDatawithECDSA(ockContext.getId(), digestBytes, digestBytesLen, ecPrivateKeyId);
    }

    @Override
    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes, int digestBytesLen, byte[] sigBytes, int sigBytesLen,
            long ecPublicKeyId) throws OCKException {
        return NativeOCKImplementation.ECKEY_verifyDatawithECDSA(ockContext.getId(), digestBytes, digestBytesLen,
            sigBytes, sigBytesLen, ecPublicKeyId);
    }

    @Override
    public long HKDF_create(String digestAlgo) throws OCKException {
        return NativeOCKImplementation.HKDF_create(ockContext.getId(), digestAlgo);
    }

    @Override
    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen)
            throws OCKException {
        return NativeOCKImplementation.HKDF_extract(ockContext.getId(), hkdfId, saltBytes, saltLen, inKey, inKeyLen);
    }

    @Override
    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes, long prkBytesLen, byte[] info, long infoLen, long okmLen)
            throws OCKException {
        return NativeOCKImplementation.HKDF_expand(ockContext.getId(), hkdfId, prkBytes, prkBytesLen, info, infoLen, okmLen);
    }

    @Override
    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen, byte[] info,
            long infoLen, long okmLen) throws OCKException {
        return NativeOCKImplementation.HKDF_derive(ockContext.getId(), hkdfId,
            saltBytes, saltLen, inKey, inKeyLen, info, infoLen, okmLen);
    }

    @Override
    public void HKDF_delete(long hkdfId) throws OCKException {
        NativeOCKImplementation.HKDF_delete(ockContext.getId(), hkdfId);
    }

    @Override
    public int HKDF_size(long hkdfId) throws OCKException {
        return NativeOCKImplementation.HKDF_size(ockContext.getId(), hkdfId);
    }

    @Override
    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt, int iterations, int keyLength)
            throws OCKException {
        return NativeOCKImplementation.PBKDF2_derive(ockContext.getId(), hashAlgorithm, password, salt, iterations, keyLength);
    }

    @Override
    public long MLKEY_generate(String cipherName)
            throws OCKException {
        return NativeOCKImplementation.MLKEY_generate(ockContext.getId(), cipherName);
    }

    @Override
    public long MLKEY_createPrivateKey(String cipherName, byte[] privateKeyBytes)
            throws OCKException {
        return NativeOCKImplementation.MLKEY_createPrivateKey(ockContext.getId(), cipherName, privateKeyBytes);
    }

    @Override
    public long MLKEY_createPublicKey(String cipherName, byte[] publicKeyBytes)
            throws OCKException {
        return NativeOCKImplementation.MLKEY_createPublicKey(ockContext.getId(), cipherName, publicKeyBytes);
    }

    @Override
    public byte[] MLKEY_getPrivateKeyBytes(long mlkeyId)
            throws OCKException {
        return NativeOCKImplementation.MLKEY_getPrivateKeyBytes(ockContext.getId(), mlkeyId);
    }

    @Override
    public byte[] MLKEY_getPublicKeyBytes(long mlkeyId)
            throws OCKException {
        return NativeOCKImplementation.MLKEY_getPublicKeyBytes(ockContext.getId(), mlkeyId);
    }

    @Override
    public void MLKEY_delete(long mlkeyId) {
        NativeOCKImplementation.MLKEY_delete(ockContext.getId(), mlkeyId);
    }

    @Override
    public void KEM_encapsulate(long ockPKeyId, byte[] wrappedKey, byte[] randomKey)
            throws OCKException {
        NativeOCKImplementation.KEM_encapsulate(ockContext.getId(), ockPKeyId, wrappedKey, randomKey);
    }

    @Override
    public byte[] KEM_decapsulate(long ockPKeyId, byte[] wrappedKey)
            throws OCKException {
        return NativeOCKImplementation.KEM_decapsulate(ockContext.getId(), ockPKeyId, wrappedKey);
    }

    @Override
    public byte[] PQC_SIGNATURE_sign(long ockPKeyId, byte[] data)
            throws OCKException {
        return NativeOCKImplementation.PQC_SIGNATURE_sign(ockContext.getId(), ockPKeyId, data);
    }

    @Override
    public boolean PQC_SIGNATURE_verify(long ockPKeyId, byte[] sigBytes, byte[] data)
            throws OCKException {
        return NativeOCKImplementation.PQC_SIGNATURE_verify(ockContext.getId(), ockPKeyId, sigBytes, data);
    }
}
