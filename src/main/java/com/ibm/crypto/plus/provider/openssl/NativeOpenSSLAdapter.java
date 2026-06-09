/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeInterface;
import java.nio.ByteBuffer;
import java.security.ProviderException;
import sun.security.util.Debug;

public abstract class NativeOpenSSLAdapter implements NativeInterface {
    // These code values must match those defined in Context.h.
    //
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OCK_INSTALL_PATH = 1;
    private static final int VALUE_OCK_VERSION = 2;

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    static final String unobtainedValue = new String();

    // whether to validate OpenSSL was loaded from JRE location
    private static final boolean validateOSSLLocation = true;

    private OpenSSLContext osslContext = null;
    private boolean osslInitialized = false;
    private boolean useFIPSMode;

    private String osslVersion = unobtainedValue;
    private String osslInstallPath = unobtainedValue;

    // The following is a special String instance to indicate that a
    // value has not yet been obtained.  We do this because some values
    // may be null and we only want to query the value one time.
    //
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
        // made the method synchronizaed to ensure only one thread can execute
        // the method at a time.
        //
        if (osslInitialized) {
            return;
        }

        try {
            //long osslContextId =  NativeOpenSSLImplementation.initializeOSSL(this.useFIPSMode);
            long osslContextId = 0;
            this.osslContext = OpenSSLContext.createContext(osslContextId, this.useFIPSMode);
            /*getLibraryBuildDate();

            if (validateOSSLLocation) {
                validateLibraryLocation();
            }*/

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

    // Get OCK context for crypto operations
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
            obtainOCKVersion();
        }
        return osslVersion;
    }

    @Override
    public String getLibraryInstallPath() throws OpenSSLException {
        if (osslInstallPath == unobtainedValue) {
            obtainOCKInstallPath();
        }
        return osslInstallPath;
    }


    private synchronized void obtainOCKVersion() throws OpenSSLException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (osslVersion == unobtainedValue) {
            osslVersion = CTX_getValue(VALUE_OCK_VERSION);
        }
    }

    private synchronized void obtainOCKInstallPath() throws OpenSSLException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (osslInstallPath == unobtainedValue) {
            osslInstallPath = CTX_getValue(VALUE_OCK_INSTALL_PATH);
        }
    }

    static public ProviderException providerException(String message, Throwable throwable) {
        return new ProviderException(message, throwable);
    }

    @Override
    public void validateLibraryLocation() throws ProviderException, OpenSSLException {
        /*if (NativeOpenSSLImplementation.requirePreloadOSSL == false) {
            // If we are not requiring OCK to be pre-loaded, then it does not need to be
            // loaded from the JRE location
            //
            return;
        }

        try {
            // Check to make sure that the OCK install path is within the JRE
            //
            String ockLoadPath = new File(NativeOpenSSLImplementation.getOSSLLoadFile()).getCanonicalPath();
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
        }*/
    }

    @Override
    public void validateLibraryVersion() throws ProviderException, OpenSSLException {
        if (NativeOpenSSLImplementation.requirePreloadOSSL == false) {
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
        /*String ockLoadPath = NativeOpenSSLImplementation.getOSSLLoadFile();
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
        }*/

        return null;
    }

    @Override
    public String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeOpenSSLImplementation.getLibraryBuildDate();;
        }
        return libraryBuildDate;
    }

    @Override
    public long initializeNative(boolean isFIPS) throws OpenSSLException {
        //return NativeOpenSSLImplementation.initializeOSSL(isFIPS);
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
    public void EXTRAND_nextBytes(long ockPRNGContextId, byte[] buffer) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_nextBytes(osslContext.getId(), ockPRNGContextId, buffer);
    }

    @Override
    public void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_setSeed(osslContext.getId(), ockPRNGContextId, seed);
    }

    @Override
    public void EXTRAND_delete(long ockPRNGContextId) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_delete(osslContext.getId(), ockPRNGContextId);
    }

    @Override
    public long CIPHER_create(String cipher) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_create(osslContext.getId(), cipher);
    }

    @Override
    public void CIPHER_init(long ockCipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_init(osslContext.getId(), ockCipherId, isEncrypt, paddingId, key, iv);
    }

    @Override
    public void CIPHER_clean(long ockCipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_clean(osslContext.getId(), ockCipherId);
    }

    @Override
    public void CIPHER_setPadding(long ockCipherId, int paddingId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_setPadding(osslContext.getId(), ockCipherId, paddingId);
    }

    @Override
    public int CIPHER_getBlockSize(long ockCipherId) {
        return NativeOpenSSLImplementation.CIPHER_getBlockSize(osslContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_getKeyLength(long ockCipherId) {
        return NativeOpenSSLImplementation.CIPHER_getKeyLength(osslContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_getIVLength(long ockCipherId) {
        return NativeOpenSSLImplementation.CIPHER_getIVLength(osslContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_getOID(long ockCipherId) {
        return NativeOpenSSLImplementation.CIPHER_getOID(osslContext.getId(), ockCipherId);
    }

    @Override
    public int CIPHER_encryptUpdate(long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_encryptUpdate(osslContext.getId(), ockCipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptUpdate(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_decryptUpdate(osslContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public int CIPHER_encryptFinal(long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_encryptFinal(osslContext.getId(), ockCipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptFinal(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_decryptFinal(osslContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public long checkHardwareSupport() {
        return NativeOpenSSLImplementation.checkHardwareSupport(osslContext.getId());
    }

    @Override
    public void CIPHER_delete(long ockCipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_delete(osslContext.getId(), ockCipherId);
    }

    @Override
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_KeyWraporUnwrap(osslContext.getId(), key, KEK, type);
    }

    @Override
    public int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer,
            int inputLength, int mode) {
        return NativeOpenSSLImplementation.z_kmc_native(input, inputOffset, output, outputOffset, paramPointer, inputLength, mode);
    }

    @Override
    public long POLY1305CIPHER_create(String cipher) throws OpenSSLException {
        return NativeOpenSSLImplementation.POLY1305CIPHER_create(osslContext.getId(), cipher);
    }

    @Override
    public void POLY1305CIPHER_init(long ockCipherId, int isEncrypt, byte[] key, byte[] iv) throws OpenSSLException {
        NativeOpenSSLImplementation.POLY1305CIPHER_init(osslContext.getId(), ockCipherId, isEncrypt, key, iv);
    }

    @Override
    public void POLY1305CIPHER_clean(long ockCipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.POLY1305CIPHER_clean(osslContext.getId(), ockCipherId);
    }

    @Override
    public void POLY1305CIPHER_setPadding(long ockCipherId, int paddingId) throws OpenSSLException {
        NativeOpenSSLImplementation.POLY1305CIPHER_setPadding(osslContext.getId(), ockCipherId, paddingId);
    }

    @Override
    public int POLY1305CIPHER_getBlockSize(long ockCipherId) {
        return NativeOpenSSLImplementation.POLY1305CIPHER_getBlockSize(osslContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getKeyLength(long ockCipherId) {
        return NativeOpenSSLImplementation.POLY1305CIPHER_getKeyLength(osslContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getIVLength(long ockCipherId) {
        return NativeOpenSSLImplementation.POLY1305CIPHER_getIVLength(osslContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getOID(long ockCipherId) {
        return NativeOpenSSLImplementation.POLY1305CIPHER_getOID(osslContext.getId(), ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_encryptUpdate(long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.POLY1305CIPHER_encryptUpdate(osslContext.getId(), ockCipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int POLY1305CIPHER_decryptUpdate(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.POLY1305CIPHER_decryptUpdate(osslContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int POLY1305CIPHER_encryptFinal(long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] tag) throws OpenSSLException {
        return NativeOpenSSLImplementation.POLY1305CIPHER_encryptFinal(osslContext.getId(), ockCipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, tag);
    }

    @Override
    public int POLY1305CIPHER_decryptFinal(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] tag) throws OpenSSLException {
        return NativeOpenSSLImplementation.POLY1305CIPHER_decryptFinal(osslContext.getId(), ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, tag);
    }

    @Override
    public void POLY1305CIPHER_delete(long ockCipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.POLY1305CIPHER_delete(osslContext.getId(), ockCipherId);
    }

    @Override
    public long do_GCM_checkHardwareGCMSupport() {
        return NativeOpenSSLImplementation.do_GCM_checkHardwareGCMSupport(osslContext.getId());
    }

    @Override
    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen,
            inOffset, inLen, ciphertextOffset, aadLen, tagLen, parameterBuffer,
            input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset,
            int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_encryptFastJNI(osslContext.getId(), gcmCtx, keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen,
            int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_decryptFastJNI(osslContext.getId(), gcmCtx, keyLen, ivLen,
            ciphertextOffset, ciphertextLen, plainOffset, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset,
            int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_encrypt(osslContext.getId(), gcmCtx, key, keyLen, iv, ivLen,
            input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tag, tagLen);
    }

    @Override
    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext,
            int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_decrypt(osslContext.getId(), gcmCtx, key, keyLen, iv, ivLen,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, aad, aadLen, tagLen);
    }

    @Override
    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag,
            int tagLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_FinalForUpdateEncrypt(osslContext.getId(), gcmCtx, key, keyLen, iv, ivLen,
            input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tag, tagLen);
    }

    @Override
    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_FinalForUpdateDecrypt(osslContext.getId(), gcmCtx,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, plaintextlen, aad, aadLen, tagLen);
    }

    @Override
    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_UpdForUpdateEncrypt(osslContext.getId(), gcmCtx,
            input, inOffset, inLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_UpdForUpdateDecrypt(osslContext.getId(), gcmCtx,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_InitForUpdateEncrypt(osslContext.getId(), gcmCtx,
            key, keyLen, iv, ivLen, aad, aadLen);
    }

    @Override
    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_GCM_InitForUpdateDecrypt(osslContext.getId(), gcmCtx,
            key, keyLen, iv, ivLen, aad, aadLen);
    }

    @Override
    public void do_GCM_delete() throws OpenSSLException {
        NativeOpenSSLImplementation.do_GCM_delete(osslContext.getId());
    }

    @Override
    public void free_GCM_ctx(long gcmContextId) throws OpenSSLException {
        NativeOpenSSLImplementation.free_GCM_ctx(osslContext.getId(), gcmContextId);
    }

    @Override
    public long create_GCM_context() throws OpenSSLException {
        return NativeOpenSSLImplementation.create_GCM_context(osslContext.getId());
    }

    @Override
    public long do_CCM_checkHardwareCCMSupport() {
        return NativeOpenSSLImplementation.do_CCM_checkHardwareCCMSupport(osslContext.getId());
    }

    @Override
    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_CCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_CCM_encryptFastJNI(int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_CCM_encryptFastJNI(osslContext.getId(), keyLen, ivLen, inLen,
            ciphertextLen, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_CCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_CCM_decryptFastJNI(int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_CCM_decryptFastJNI(osslContext.getId(), keyLen, ivLen, ciphertextLen,
            plaintextLen, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input,
            int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_CCM_encrypt(osslContext.getId(), iv, ivLen, key, keyLen,
            aad, aadLen, input, inLen, ciphertext, ciphertextLen, tagLen);
    }

    @Override
    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] ciphertext,
            int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.do_CCM_decrypt(osslContext.getId(), iv, ivLen, key, keyLen,
            aad, aadLen, ciphertext, ciphertextLength, plaintext, plaintextLength, tagLen);
    }

    @Override
    public void do_CCM_delete() throws OpenSSLException {
        NativeOpenSSLImplementation.do_CCM_delete(osslContext.getId());
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
    public void KEM_encapsulate(long ockPKeyId, byte[] wrappedKey, byte[] randomKey)
            throws OpenSSLException {
        NativeOpenSSLImplementation.KEM_encapsulate(osslContext.getId(), ockPKeyId, wrappedKey, randomKey);
    }

    @Override
    public byte[] KEM_decapsulate(long ockPKeyId, byte[] wrappedKey)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.KEM_decapsulate(osslContext.getId(), ockPKeyId, wrappedKey);
    }

    @Override
    public byte[] PQC_SIGNATURE_sign(long ockPKeyId, byte[] data)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.PQC_SIGNATURE_sign(osslContext.getId(), ockPKeyId, data);
    }

    @Override
    public boolean PQC_SIGNATURE_verify(long ockPKeyId, byte[] sigBytes, byte[] data)
            throws OpenSSLException {
        return NativeOpenSSLImplementation.PQC_SIGNATURE_verify(osslContext.getId(), ockPKeyId, sigBytes, data);
    }
}

