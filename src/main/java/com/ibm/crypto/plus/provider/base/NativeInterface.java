/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.nio.ByteBuffer;
import java.security.ProviderException;

public interface NativeInterface {
    public String getLibraryVersion() throws NativeException;

    public String getLibraryInstallPath() throws NativeException;

    void validateLibraryLocation() throws ProviderException, NativeException;

    void validateLibraryVersion() throws ProviderException, NativeException;

    // =========================================================================
    // General functions
    // =========================================================================

    public String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    public long initializeOCK(boolean isFIPS) throws NativeException;

    public String CTX_getValue(int valueId) throws NativeException;

    public long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    public void RAND_nextBytes(byte[] buffer) throws NativeException;

    public void RAND_setSeed(byte[] seed) throws NativeException;

    public void RAND_generateSeed(byte[] seed) throws NativeException;

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    public long EXTRAND_create(String algName) throws NativeException;

    public void EXTRAND_nextBytes(long ockPRNGContextId,
            byte[] buffer) throws NativeException;

    public void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed)
            throws NativeException;

    public void EXTRAND_delete(long ockPRNGContextId)
            throws NativeException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    public long CIPHER_create(String cipher) throws NativeException;

    public void CIPHER_init(long ockCipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv) throws NativeException;

    public void CIPHER_clean(long ockCipherId) throws NativeException;

    public void CIPHER_setPadding(long ockCipherId, int paddingId)
            throws NativeException;

    public int CIPHER_getBlockSize(long ockCipherId);

    public int CIPHER_getKeyLength(long ockCipherId);

    public int CIPHER_getIVLength(long ockCipherId);

    public int CIPHER_getOID(long ockCipherId);

    public int CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws NativeException;

    public int CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws NativeException;

    public int CIPHER_encryptFinal(long ockCipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit)
            throws NativeException;

    public int CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws NativeException;

    public long checkHardwareSupport();

    public void CIPHER_delete(long ockCipherId)
            throws NativeException;
            
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type)
            throws NativeException;

    public int z_kmc_native(byte[] input, int inputOffset, byte[] output,
            int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    public long POLY1305CIPHER_create(String cipher)
            throws NativeException;

    public void POLY1305CIPHER_init(long ockCipherId,
            int isEncrypt, byte[] key, byte[] iv) throws NativeException;

    public void POLY1305CIPHER_clean(long ockCipherId)
            throws NativeException;

    public void POLY1305CIPHER_setPadding(long ockCipherId,
            int paddingId) throws NativeException;

    public int POLY1305CIPHER_getBlockSize(long ockCipherId);

    public int POLY1305CIPHER_getKeyLength(long ockCipherId);

    public int POLY1305CIPHER_getIVLength(long ockCipherId);

    public int POLY1305CIPHER_getOID(long ockCipherId);

    public int POLY1305CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset) throws NativeException;

    public int POLY1305CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws NativeException;

    public int POLY1305CIPHER_encryptFinal(long ockCipherId,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset,
            byte[] tag) throws NativeException;

    public int POLY1305CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, byte[] tag) throws NativeException;

    public void POLY1305CIPHER_delete(long ockCipherId)
            throws NativeException;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    public long do_GCM_checkHardwareGCMSupport();

    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws NativeException;

    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws NativeException;

    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws NativeException;

    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws NativeException;

    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx,
            byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws NativeException;

    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx,
            /* byte[] key, int keyLen,
             byte[] iv, int ivLen,*/
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws NativeException;

    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset)
            throws NativeException;

    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws NativeException;

    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws NativeException;

    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws NativeException;


    public void do_GCM_delete() throws NativeException;

    public void free_GCM_ctx(long gcmContextId)
            throws NativeException;

    //public int get_GCM_TLSEnabled() throws NativeException;

    public long create_GCM_context() throws NativeException;

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    public long do_CCM_checkHardwareCCMSupport();

    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    public int do_CCM_encryptFastJNI(int keyLen, int ivLen,
            int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws NativeException;

    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    public int do_CCM_decryptFastJNI(int keyLen, int ivLen,
            int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws NativeException;

    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext,
            int ciphertextLen, int tagLen) throws NativeException;

    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength,
            byte[] plaintext, int plaintextLength, int tagLen) throws NativeException;

    public void do_CCM_delete() throws NativeException;

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    public int RSACIPHER_public_encrypt(long rsaKeyId,
            int rsaPaddingId, int mdId, int mgf1Id, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws NativeException;

    public int RSACIPHER_private_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws NativeException;

    public int RSACIPHER_public_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset) throws NativeException;

    public int RSACIPHER_private_decrypt(long rsaKeyId,
            int rsaPaddingId, int mdId, int mgf1Id, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey)
            throws NativeException;

    // =========================================================================
    // DH key functions
    // =========================================================================

    public long DHKEY_generate(int numBits) throws NativeException;

    public byte[] DHKEY_generateParameters(int numBits);

    public long DHKEY_generate(byte[] dhParameters)
            throws NativeException;

    public long DHKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    public long DHKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    public byte[] DHKEY_getParameters(long dhKeyId);

    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId)
            throws NativeException;

    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId)
            throws NativeException;

    public long DHKEY_createPKey(long dhKeyId) throws NativeException;

    public byte[] DHKEY_computeDHSecret(long pubKeyId,
            long privKeyId) throws NativeException;

    public void DHKEY_delete(long dhKeyId) throws NativeException;

    // =========================================================================
    // RSA key functions
    // =========================================================================

    public long RSAKEY_generate(int numBits, long e)
            throws NativeException;

    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    public long RSAKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId)
            throws NativeException;

    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId)
            throws NativeException;

    public int RSAKEY_size(long rsaKeyId);

    public void RSAKEY_delete(long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    public long DSAKEY_generate(int numBits) throws NativeException;

    public byte[] DSAKEY_generateParameters(int numBits);

    public long DSAKEY_generate(byte[] dsaParameters)
            throws NativeException;

    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    public long DSAKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    public byte[] DSAKEY_getParameters(long dsaKeyId);

    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId)
            throws NativeException;

    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId)
            throws NativeException;

    public long DSAKEY_createPKey(long dsaKeyId)
            throws NativeException;

    public void DSAKEY_delete(long dsaKeyId) throws NativeException;

    // =========================================================================
    // PKey functions
    // =========================================================================

    public void PKEY_delete(long pkeyId) throws NativeException;

    // =========================================================================
    // Digest functions
    // =========================================================================

    public long DIGEST_create(String digestAlgo)
            throws NativeException;

    public long DIGEST_copy(long digestId)
            throws NativeException;

    public int DIGEST_update(long digestId, byte[] input,
            int offset, int length) throws NativeException;

    public void DIGEST_updateFastJNI(long digestId,
            long inputBuffer, int length) throws NativeException;

    public byte[] DIGEST_digest(long digestId) throws NativeException;

    public void DIGEST_digest_and_reset(long digestId,
            long outputBuffer, int length) throws NativeException;

    public int DIGEST_digest_and_reset(long digestId,
            byte[] output) throws NativeException;

    public int DIGEST_size(long digestId) throws NativeException;

    public void DIGEST_reset(long digestId) throws NativeException;

    public void DIGEST_delete(long digestId) throws NativeException;

    public int DIGEST_PKCS12KeyDeriveHelp(long digestId, byte[] input,
            int offset, int length, int iterationCount) throws NativeException;

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    public byte[] SIGNATURE_sign(long digestId, long pkeyId,
            boolean convert) throws NativeException;

    public boolean SIGNATURE_verify(long digestId, long pkeyId,
            byte[] sigBytes) throws NativeException;

    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId,
            byte[] bytes) throws NativeException;

    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId,
            byte[] sigBytes, byte[] oneShot) throws NativeException;

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    public int RSAPSS_signInit(long rsaPssId, long pkeyId,
            int saltlen, boolean convert) throws NativeException;

    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId,
            int saltlen) throws NativeException;

    public int RSAPSS_getSigLen(long rsaPssId);

    public void RSAPSS_signFinal(long rsaPssId, byte[] signature,
            int length) throws NativeException;

    public boolean RSAPSS_verifyFinal(long rsaPssId,
            byte[] sigBytes, int length) throws NativeException;

    public long RSAPSS_createContext(String digestAlgo,
            String mgf1SpecAlgo) throws NativeException;

    public void RSAPSS_releaseContext(long rsaPssId)
            throws NativeException;

    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input,
            int offset, int length) throws NativeException;

    public void RSAPSS_reset(long digestId) throws NativeException;

    public void RSAPSS_resetDigest(long rsaPssId)
            throws NativeException;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    public byte[] DSANONE_SIGNATURE_sign(byte[] digest,
            long dsaKeyId) throws NativeException;

    public boolean DSANONE_SIGNATURE_verify(byte[] digest,
            long dsaKeyId, byte[] sigBytes) throws NativeException;

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    public byte[] RSASSL_SIGNATURE_sign(byte[] digest,
            long rsaKeyId) throws NativeException;

    public boolean RSASSL_SIGNATURE_verify(byte[] digest,
            long rsaKeyId, byte[] sigBytes, boolean convert) throws NativeException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    public long HMAC_create(String digestAlgo) throws NativeException;

    public int HMAC_update(long hmacId, byte[] key, int keyLength,
            byte[] input, int inputOffset, int inputLength, boolean needInit) throws NativeException;

    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength,
            byte[] hmac, boolean needInit) throws NativeException;

    public int HMAC_size(long hmacId) throws NativeException;

    public void HMAC_delete(long hmacId) throws NativeException;

    // =========================================================================
    // EC key functions
    // =========================================================================

    public long ECKEY_generate(int numBits) throws NativeException;

    public long ECKEY_generate(String curveOid)
            throws NativeException;

    public long XECKEY_generate(int option, long bufferPtr)
            throws NativeException;

    public byte[] ECKEY_generateParameters(int numBits)
            throws NativeException;

    public byte[] ECKEY_generateParameters(String curveOid)
            throws NativeException;

    public long ECKEY_generate(byte[] ecParameters)
            throws NativeException;

    public long ECKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    public long XECKEY_createPrivateKey(byte[] privateKeyBytes,
            long bufferPtr) throws NativeException;

    public long ECKEY_createPublicKey(byte[] publicKeyBytes,
            byte[] parameterBytes) throws NativeException;

    public long XECKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    public byte[] ECKEY_getParameters(long ecKeyId);

    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId)
            throws NativeException;

    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId)
            throws NativeException;

    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId)
            throws NativeException;

    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId)
            throws NativeException;

    public long ECKEY_createPKey(long ecKeyId) throws NativeException;

    public void ECKEY_delete(long ecKeyId) throws NativeException;

    public void XECKEY_delete(long xecKeyId) throws NativeException;

    public long XDHKeyAgreement_init(long privId);

    public void XDHKeyAgreement_setPeer(long genCtx, long pubId);

    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId,
            long privEcKeyId) throws NativeException;

    public byte[] XECKEY_computeECDHSecret(long genCtx,
            long pubEcKeyId, long privEcKeyId, int secrectBufferSize) throws NativeException;


    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, long ecPrivateKeyId) throws NativeException;

    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId)
            throws NativeException;


    // =========================================================================
    // HKDF functions
    // =========================================================================

    public long HKDF_create(String digestAlgo) throws NativeException;

    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen) throws NativeException;

    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes,
            long prkBytesLen, byte[] info, long infoLen, long okmLen) throws NativeException;

    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen)
            throws NativeException;

    public void HKDF_delete(long hkdfId) throws NativeException;

    public int HKDF_size(long hkdfId) throws NativeException;

    // =========================================================================
    // Password based key derivation functions ( PBKDF )
    // =========================================================================

    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt,
            int iterations, int keyLength) throws NativeException;

    // =========================================================================
    // ML-KEY key functions
    // =========================================================================

    public long MLKEY_generate(String cipherName)
            throws NativeException;

    public long MLKEY_createPrivateKey(String cipherName, byte[] privateKeyBytes)
            throws NativeException;

    public long MLKEY_createPublicKey(String cipherName, byte[] publicKeyBytes)
            throws NativeException;

    public byte[] MLKEY_getPrivateKeyBytes(long mlkeyId)
            throws NativeException;

    public byte[] MLKEY_getPublicKeyBytes(long mlkeyId)
            throws NativeException;

    public void MLKEY_delete(long mlkeyId);

    // =========================================================================
    // Key Encapsulation functions
    // =========================================================================
    public void KEM_encapsulate(long ockPKeyId, byte[] wrappedKey, byte[] randomKey)
            throws NativeException;

    public byte[] KEM_decapsulate(long ockPKeyId, byte[] wrappedKey)
            throws NativeException;

    // =========================================================================
    // PQC Signture functions - for use with ML-DSA and ML-SLH
    // =========================================================================
    public byte[] PQC_SIGNATURE_sign(long ockPKeyId, byte[] data)
            throws NativeException;

    public boolean PQC_SIGNATURE_verify(long ockPKeyId, byte[] sigBytes, byte[] data)
            throws NativeException;
}
