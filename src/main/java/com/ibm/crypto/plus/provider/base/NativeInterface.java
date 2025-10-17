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
    public String getLibraryVersion() throws OCKException;

    public String getLibraryInstallPath() throws OCKException;

    void validateLibraryLocation() throws ProviderException, OCKException;

    void validateLibraryVersion() throws ProviderException, OCKException;

    // =========================================================================
    // General functions
    // =========================================================================

    public String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    public long initializeOCK(boolean isFIPS) throws OCKException;

    public String CTX_getValue(int valueId) throws OCKException;

    public long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    public void RAND_nextBytes(byte[] buffer) throws OCKException;

    public void RAND_setSeed(byte[] seed) throws OCKException;

    public void RAND_generateSeed(byte[] seed) throws OCKException;

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    public long EXTRAND_create(String algName) throws OCKException;

    public void EXTRAND_nextBytes(long ockPRNGContextId,
            byte[] buffer) throws OCKException;

    public void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed)
            throws OCKException;

    public void EXTRAND_delete(long ockPRNGContextId)
            throws OCKException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    public long CIPHER_create(String cipher) throws OCKException;

    public void CIPHER_init(long ockCipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv) throws OCKException;

    public void CIPHER_clean(long ockCipherId) throws OCKException;

    public void CIPHER_setPadding(long ockCipherId, int paddingId)
            throws OCKException;

    public int CIPHER_getBlockSize(long ockCipherId);

    public int CIPHER_getKeyLength(long ockCipherId);

    public int CIPHER_getIVLength(long ockCipherId);

    public int CIPHER_getOID(long ockCipherId);

    public int CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OCKException;

    public int CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws OCKException;

    public int CIPHER_encryptFinal(long ockCipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit)
            throws OCKException;

    public int CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws OCKException;

    public long checkHardwareSupport();

    public void CIPHER_delete(long ockCipherId)
            throws OCKException;
            
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type)
            throws OCKException;

    public int z_kmc_native(byte[] input, int inputOffset, byte[] output,
            int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    public long POLY1305CIPHER_create(String cipher)
            throws OCKException;

    public void POLY1305CIPHER_init(long ockCipherId,
            int isEncrypt, byte[] key, byte[] iv) throws OCKException;

    public void POLY1305CIPHER_clean(long ockCipherId)
            throws OCKException;

    public void POLY1305CIPHER_setPadding(long ockCipherId,
            int paddingId) throws OCKException;

    public int POLY1305CIPHER_getBlockSize(long ockCipherId);

    public int POLY1305CIPHER_getKeyLength(long ockCipherId);

    public int POLY1305CIPHER_getIVLength(long ockCipherId);

    public int POLY1305CIPHER_getOID(long ockCipherId);

    public int POLY1305CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset) throws OCKException;

    public int POLY1305CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws OCKException;

    public int POLY1305CIPHER_encryptFinal(long ockCipherId,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset,
            byte[] tag) throws OCKException;

    public int POLY1305CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, byte[] tag) throws OCKException;

    public void POLY1305CIPHER_delete(long ockCipherId)
            throws OCKException;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    public long do_GCM_checkHardwareGCMSupport();

    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException;

    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OCKException;

    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OCKException;

    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OCKException;

    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx,
            byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OCKException;

    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx,
            /* byte[] key, int keyLen,
             byte[] iv, int ivLen,*/
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OCKException;

    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset)
            throws OCKException;

    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws OCKException;

    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OCKException;

    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OCKException;


    public void do_GCM_delete() throws OCKException;

    public void free_GCM_ctx(long gcmContextId)
            throws OCKException;

    //public int get_GCM_TLSEnabled() throws OCKException;

    public long create_GCM_context() throws OCKException;

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    public long do_CCM_checkHardwareCCMSupport();

    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    public int do_CCM_encryptFastJNI(int keyLen, int ivLen,
            int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws OCKException;

    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws OCKException;

    public int do_CCM_decryptFastJNI(int keyLen, int ivLen,
            int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws OCKException;

    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext,
            int ciphertextLen, int tagLen) throws OCKException;

    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength,
            byte[] plaintext, int plaintextLength, int tagLen) throws OCKException;

    public void do_CCM_delete() throws OCKException;

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    public int RSACIPHER_public_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OCKException;

    public int RSACIPHER_private_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OCKException;

    public int RSACIPHER_public_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset) throws OCKException;

    public int RSACIPHER_private_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset, boolean convertKey) throws OCKException;

    // =========================================================================
    // DH key functions
    // =========================================================================

    public long DHKEY_generate(int numBits) throws OCKException;

    public byte[] DHKEY_generateParameters(int numBits);

    public long DHKEY_generate(byte[] dhParameters)
            throws OCKException;

    public long DHKEY_createPrivateKey(byte[] privateKeyBytes)
            throws OCKException;

    public long DHKEY_createPublicKey(byte[] publicKeyBytes)
            throws OCKException;

    public byte[] DHKEY_getParameters(long dhKeyId);

    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId)
            throws OCKException;

    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId)
            throws OCKException;

    public long DHKEY_createPKey(long dhKeyId) throws OCKException;

    public byte[] DHKEY_computeDHSecret(long pubKeyId,
            long privKeyId) throws OCKException;

    public void DHKEY_delete(long dhKeyId) throws OCKException;

    // =========================================================================
    // RSA key functions
    // =========================================================================

    public long RSAKEY_generate(int numBits, long e)
            throws OCKException;

    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes)
            throws OCKException;

    public long RSAKEY_createPublicKey(byte[] publicKeyBytes)
            throws OCKException;

    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId)
            throws OCKException;

    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId)
            throws OCKException;

    public long RSAKEY_createPKey(long rsaKeyId)
            throws OCKException;

    public int RSAKEY_size(long rsaKeyId);

    public void RSAKEY_delete(long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    public long DSAKEY_generate(int numBits) throws OCKException;

    public byte[] DSAKEY_generateParameters(int numBits);

    public long DSAKEY_generate(byte[] dsaParameters)
            throws OCKException;

    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes)
            throws OCKException;

    public long DSAKEY_createPublicKey(byte[] publicKeyBytes)
            throws OCKException;

    public byte[] DSAKEY_getParameters(long dsaKeyId);

    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId)
            throws OCKException;

    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId)
            throws OCKException;

    public long DSAKEY_createPKey(long dsaKeyId)
            throws OCKException;

    public void DSAKEY_delete(long dsaKeyId) throws OCKException;

    // =========================================================================
    // PKey functions
    // =========================================================================

    public void PKEY_delete(long pkeyId) throws OCKException;

    // =========================================================================
    // Digest functions
    // =========================================================================

    public long DIGEST_create(String digestAlgo)
            throws OCKException;

    public long DIGEST_copy(long digestId)
            throws OCKException;

    public int DIGEST_update(long digestId, byte[] input,
            int offset, int length) throws OCKException;

    public void DIGEST_updateFastJNI(long digestId,
            long inputBuffer, int length) throws OCKException;

    public byte[] DIGEST_digest(long digestId) throws OCKException;

    public void DIGEST_digest_and_reset(long digestId,
            long outputBuffer, int length) throws OCKException;

    public int DIGEST_digest_and_reset(long digestId,
            byte[] output) throws OCKException;

    public int DIGEST_size(long digestId) throws OCKException;

    public void DIGEST_reset(long digestId) throws OCKException;

    public void DIGEST_delete(long digestId) throws OCKException;

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    public byte[] SIGNATURE_sign(long digestId, long pkeyId,
            boolean convert) throws OCKException;

    public boolean SIGNATURE_verify(long digestId, long pkeyId,
            byte[] sigBytes) throws OCKException;

    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId,
            byte[] bytes) throws OCKException;

    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId,
            byte[] sigBytes, byte[] oneShot) throws OCKException;

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    public int RSAPSS_signInit(long rsaPssId, long pkeyId,
            int saltlen, boolean convert) throws OCKException;

    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId,
            int saltlen) throws OCKException;

    public int RSAPSS_getSigLen(long rsaPssId);

    public void RSAPSS_signFinal(long rsaPssId, byte[] signature,
            int length) throws OCKException;

    public boolean RSAPSS_verifyFinal(long rsaPssId,
            byte[] sigBytes, int length) throws OCKException;

    public long RSAPSS_createContext(String digestAlgo,
            String mgf1SpecAlgo) throws OCKException;

    public void RSAPSS_releaseContext(long rsaPssId)
            throws OCKException;

    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input,
            int offset, int length) throws OCKException;

    public void RSAPSS_reset(long digestId) throws OCKException;

    public void RSAPSS_resetDigest(long rsaPssId)
            throws OCKException;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    public byte[] DSANONE_SIGNATURE_sign(byte[] digest,
            long dsaKeyId) throws OCKException;

    public boolean DSANONE_SIGNATURE_verify(byte[] digest,
            long dsaKeyId, byte[] sigBytes) throws OCKException;

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    public byte[] RSASSL_SIGNATURE_sign(byte[] digest,
            long rsaKeyId) throws OCKException;

    public boolean RSASSL_SIGNATURE_verify(byte[] digest,
            long rsaKeyId, byte[] sigBytes, boolean convert) throws OCKException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    public long HMAC_create(String digestAlgo) throws OCKException;

    public int HMAC_update(long hmacId, byte[] key, int keyLength,
            byte[] input, int inputOffset, int inputLength, boolean needInit) throws OCKException;

    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength,
            byte[] hmac, boolean needInit) throws OCKException;

    public int HMAC_size(long hmacId) throws OCKException;

    public void HMAC_delete(long hmacId) throws OCKException;

    // =========================================================================
    // EC key functions
    // =========================================================================

    public long ECKEY_generate(int numBits) throws OCKException;

    public long ECKEY_generate(String curveOid)
            throws OCKException;

    public long XECKEY_generate(int option, long bufferPtr)
            throws OCKException;

    public byte[] ECKEY_generateParameters(int numBits)
            throws OCKException;

    public byte[] ECKEY_generateParameters(String curveOid)
            throws OCKException;

    public long ECKEY_generate(byte[] ecParameters)
            throws OCKException;

    public long ECKEY_createPrivateKey(byte[] privateKeyBytes)
            throws OCKException;

    public long XECKEY_createPrivateKey(byte[] privateKeyBytes,
            long bufferPtr) throws OCKException;

    public long ECKEY_createPublicKey(byte[] publicKeyBytes,
            byte[] parameterBytes) throws OCKException;

    public long XECKEY_createPublicKey(byte[] publicKeyBytes)
            throws OCKException;

    public byte[] ECKEY_getParameters(long ecKeyId);

    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId)
            throws OCKException;

    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId)
            throws OCKException;

    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId)
            throws OCKException;

    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId)
            throws OCKException;

    public long ECKEY_createPKey(long ecKeyId) throws OCKException;

    public void ECKEY_delete(long ecKeyId) throws OCKException;

    public void XECKEY_delete(long xecKeyId) throws OCKException;

    public long XDHKeyAgreement_init(long privId);

    public void XDHKeyAgreement_setPeer(long genCtx, long pubId);

    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId,
            long privEcKeyId) throws OCKException;

    public byte[] XECKEY_computeECDHSecret(long genCtx,
            long pubEcKeyId, long privEcKeyId, int secrectBufferSize) throws OCKException;


    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, long ecPrivateKeyId) throws OCKException;

    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId)
            throws OCKException;


    // =========================================================================
    // HKDF functions
    // =========================================================================

    public long HKDF_create(String digestAlgo) throws OCKException;

    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen) throws OCKException;

    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes,
            long prkBytesLen, byte[] info, long infoLen, long okmLen) throws OCKException;

    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen)
            throws OCKException;

    public void HKDF_delete(long hkdfId) throws OCKException;

    public int HKDF_size(long hkdfId) throws OCKException;

    // =========================================================================
    // Password based key derivation functions ( PBKDF )
    // =========================================================================

    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt,
            int iterations, int keyLength) throws OCKException;

    // =========================================================================
    // ML-KEY key functions
    // =========================================================================

    public long MLKEY_generate(String cipherName)
            throws OCKException;

    public long MLKEY_createPrivateKey(String cipherName, byte[] privateKeyBytes)
            throws OCKException;

    public long MLKEY_createPublicKey(String cipherName, byte[] publicKeyBytes)
            throws OCKException;

    public byte[] MLKEY_getPrivateKeyBytes(long mlkeyId)
            throws OCKException;

    public byte[] MLKEY_getPublicKeyBytes(long mlkeyId)
            throws OCKException;

    public void MLKEY_delete(long mlkeyId);

    // =========================================================================
    // Key Encapsulation functions
    // =========================================================================
    public void KEM_encapsulate(long ockPKeyId, byte[] wrappedKey, byte[] randomKey)
            throws OCKException;

    public byte[] KEM_decapsulate(long ockPKeyId, byte[] wrappedKey)
            throws OCKException;

    // =========================================================================
    // PQC Signture functions - for use with ML-DSA and ML-SLH
    // =========================================================================
    public byte[] PQC_SIGNATURE_sign(long ockPKeyId, byte[] data)
            throws OCKException;

    public boolean PQC_SIGNATURE_verify(long ockPKeyId, byte[] sigBytes, byte[] data)
            throws OCKException;
}
