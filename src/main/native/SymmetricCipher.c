/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>
#include <string.h>

#include <stdbool.h>
#ifdef __MVS__
#define bool _Bool
#endif

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Padding.h"
#include "Utils.h"
#include "ExceptionCodes.h"
#include <stdint.h>
#include "zHardwareFunctions.h"

typedef struct OCKCipher
{
  const ICC_EVP_CIPHER * cipher;
  ICC_EVP_CIPHER_CTX * cipherCtx;
  ICC_EVP_CIPHER_CTX * cached_context;
  int copy_context;
} OCKCipher;

// Pointers of functions that are only available on some hardware (might be null)
KMC_FuncPtr KMC; // z_kmc_native function pointer

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1create
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName)
{
  static const char * functionName = "NativeInterface.CIPHER_create";

  ICC_CTX *    ockCtx          = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher *  ockCipher       = NULL;


  const char * cipherNameChars = NULL;
  jlong        retCipher       = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (cipherName == NULL) {
    throwOCKException(env, 0, "The specified Cipher name is incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return retCipher;
  }
  ockCipher = (OCKCipher *)malloc(sizeof(OCKCipher));
  if( ockCipher == NULL ) {
    throwOCKException(env, 0, "Error allocating OCKCipher");
    if( debug ) {
      gslogFunctionExit(functionName);
    }
    return 0;
  } else {
    ockCipher->cipher = NULL;
    ockCipher->cipherCtx = NULL;
    ockCipher->cached_context = NULL;
    ockCipher->copy_context = 0;
  }

  if( !(cipherNameChars = (*env)->GetStringUTFChars(env, cipherName, NULL)) ) {
    throwOCKException(env, 0, "GetStringUTFChars() failed");
    if( debug ) {
      gslogFunctionExit(functionName);
    }
    FREE_N_NULL(ockCipher);
    return 0;
  }

  if( debug ) {
    gslogMessage("cipher=%s", cipherNameChars);
  }

  ockCipher->cipher = ICC_EVP_get_cipherbyname(ockCtx, cipherNameChars);
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
  if(cipherNameChars != NULL && strstr(cipherNameChars,"AES") != NULL && strstr(cipherNameChars,"CBC") != NULL) {
        ockCipher->copy_context = 1;
  }
#ifdef __MVS__
  #pragma convert(pop)
#endif
  if( NULL == ockCipher->cipher ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_get_cipherbyname() failed");
  } else {
    ockCipher->cipherCtx = ICC_EVP_CIPHER_CTX_new(ockCtx);
    if( NULL == ockCipher->cipherCtx ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_new failed");
    } else {
      ICC_EVP_CIPHER_CTX_init(ockCtx, ockCipher->cipherCtx);
      if (0 == ockCipher->copy_context) {
        ockCipher->cached_context = ICC_EVP_CIPHER_CTX_new(ockCtx);
        if (NULL == ockCipher->cached_context) {
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_new failed for cached context");
        }
        else {
          retCipher = (jlong)((intptr_t)ockCipher);
        }
     }
     else {
       retCipher = (jlong)((intptr_t)ockCipher);
     }
     retCipher = (jlong)((intptr_t)ockCipher);
   }
 }

 (*env)->ReleaseStringUTFChars(env, cipherName, cipherNameChars);
  if ((0 == ockCipher->copy_context) && (NULL == ockCipher->cached_context) && (NULL != ockCipher->cipherCtx) ){
  	  //cipherCtx succeeded but could not allocate cached_context, then free previously allocated cipherCtx
  	  ICC_EVP_CIPHER_CTX_free(ockCtx, ockCipher->cipherCtx);
  	  ockCipher->cipherCtx = NULL;
  }


  // If an error occurred, free up the OCKCipher allocation
  //
  if( retCipher == 0 ) {
    FREE_N_NULL(ockCipher);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return retCipher;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_init
 * Signature: (JJZ)V
 */
 JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1init
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId, jint isEncrypt,
   jint paddingId, jbyteArray key, jbyteArray iv)
{
  static const char * functionName = "NativeInterface.CIPHER_init";

  ICC_CTX *       ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher *     ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  unsigned char * keyNative = NULL;
  unsigned char * ivNative  = NULL;
  int             rc        = ICC_OSSL_SUCCESS;
  jboolean        isCopy    = 0;
  int         ockPadType   = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ( (ockCipher == NULL) || (key == NULL)) {
  	  throwOCKException(env, 0, "The specified Cipher arguments are incorrect.");
  	  if( debug ) {
  	    gslogFunctionExit(functionName);
  	  }
  	  return;
  	}
  /* Convert the key and iv to c array*/
  // iv can be null for ECB
  if( NULL != iv ) {
    ivNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,  &isCopy));
  }
  keyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));

  if( NULL == keyNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
    rc = isEncrypt ?
        ICC_EVP_EncryptInit(ockCtx, ockCipher->cipherCtx, ockCipher->cipher, keyNative, ivNative) :
        ICC_EVP_DecryptInit(ockCtx, ockCipher->cipherCtx, ockCipher->cipher, keyNative, ivNative);
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_Encrypt/DecryptInit failed");
    } else {
      switch( paddingId ) {
        case PADDING_NONE:
          ockPadType = 0;
          break;

        case PADDING_PKCS5:
          ockPadType = 1;
          break;

        default:
          throwOCKException(env, 0, "Invalid padding type");
          rc = ICC_OSSL_FAILURE;
      }

      if( rc == ICC_OSSL_SUCCESS ) {
        rc = ICC_EVP_CIPHER_CTX_set_padding(ockCtx, ockCipher->cipherCtx, ockPadType);
        if(ockCipher->copy_context == 0) {
          ockCipher->cached_context = ICC_EVP_CIPHER_CTX_new(ockCtx);
          ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cached_context, ockCipher->cipherCtx);
        }
        if( rc != ICC_OSSL_SUCCESS ) {
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_EVP_set_padding failed");
        }
      }
    }
  }

  if( keyNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
  }

  if( ivNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, iv,  ivNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_setPadding
 * Signature: (JJZ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1setPadding
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId, jint paddingId)
{
  static const char * functionName = "NativeInterface.CIPHER_setPadding";

  ICC_CTX *   ockCtx       = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher    = (OCKCipher *)((intptr_t) ockCipherId);
  int         rc           = ICC_OSSL_SUCCESS;
  int         ockPadType   = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (ockCipher == NULL) {
    if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	throwOCKException(env, 0, "The specified Cipher identifier is incorrect.");
  	return;
  }
  switch( paddingId ) {
    case PADDING_NONE:
      ockPadType = 0;
      break;

    case PADDING_PKCS5:
      ockPadType = 1;
      break;

    default:
    	throwOCKException(env, 0, "Invalid padding type");
    	rc = ICC_OSSL_FAILURE;
  }

  if( rc == ICC_OSSL_SUCCESS ) {
    rc = ICC_EVP_CIPHER_CTX_set_padding(ockCtx, ockCipher->cipherCtx, ockPadType);
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_set_padding failed");
    }
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_clean
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1clean
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId)
{
  static const char * functionName = "NativeInterface.CIPHER_clean";

  ICC_CTX *   ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  int         rc        = ICC_OSSL_SUCCESS;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (ockCipher == NULL) {
    if( debug ) {
      gslogFunctionExit(functionName);
    }
    return;
  }
  if (ockCipher->cipherCtx != NULL) {
    rc = ICC_EVP_CIPHER_CTX_cleanup(ockCtx, ockCipher->cipherCtx);
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_cleanup failed");
    }
  }
  if( debug ) {
    gslogFunctionExit(functionName);
  }
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1getBlockSize
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId)
{
  static const char * functionName = "NativeInterface.CIPHER_getBlockSize";

  ICC_CTX *   ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  int         blockSize = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
    blockSize = ICC_EVP_CIPHER_block_size(ockCtx, ockCipher->cipher);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return blockSize;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1getKeyLength
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId)
{
  static const char * functionName = "NativeInterface.CIPHER_getKeyLength";

  ICC_CTX *   ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  int         keyLength = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
    keyLength = ICC_EVP_CIPHER_key_length(ockCtx, ockCipher->cipher);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return keyLength;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1getIVLength
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId)
{
  static const char * functionName = "NativeInterface.CIPHER_getIVLength";

  ICC_CTX *   ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  int         ivLength  = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
    ivLength = ICC_EVP_CIPHER_iv_length(ockCtx, ockCipher->cipher);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return ivLength;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_getOID
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1getOID
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId)
{
  static const char * functionName = "NativeInterface.CIPHER_getOID";

  ICC_CTX *   ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  int         oid       = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
    oid = ICC_EVP_CIPHER_type(ockCtx, ockCipher->cipher);
  }
  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return oid;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    z_kmc_native
 */
JNIEXPORT int CIPHER_zKMC_internal(unsigned char* input, unsigned char* output, int inputLength, long param, int mode) {
    UDATA  len = inputLength;
    UDATA* len_udata = &len;
    UDATA  mode1 = (UDATA) mode;
    UDATA* mode_udata = &mode1;
    KMC(input, output, len_udata, param, mode_udata);
    return len;
}

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_z_1kmc_1native(JNIEnv * env, jclass clazz, jbyteArray input, jint inputOffset, jbyteArray output, jint outputOffset, jlong paramPointer, jint inputLength, jint mode)
{
  // Get input and output buffer
  jboolean isCopy = 0;
  jint len = 0;
  unsigned char* inputPointer  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input,  &isCopy)) + inputOffset;
  unsigned char* outputPointer = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, &isCopy)) + outputOffset;

  if( NULL == outputPointer || NULL == inputPointer ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  }
  else {
      len = (jint)CIPHER_zKMC_internal(inputPointer, outputPointer, (int)inputLength, (long)paramPointer, (int)mode);
  }

  if(inputPointer != NULL) (*env)->ReleasePrimitiveArrayCritical(env, input, inputPointer, 0);
  if(outputPointer != NULL) (*env)->ReleasePrimitiveArrayCritical(env, output, outputPointer, 0);
  return len;
}

JNIEXPORT int CIPHER_encryptUpdate_internal(ICC_CTX *ockCtx, OCKCipher *ockCipher, unsigned char *plaintext, int plaintextLen,
                        unsigned char *ciphertext, bool needsReinit) {
    int outLen = 0;
    if (needsReinit) {
        if (ockCipher->copy_context == 0) {
            ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx, ockCipher->cached_context);
        } else {
            ICC_EVP_EncryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
        }
    }

    int rc = ICC_EVP_EncryptUpdate(ockCtx, ockCipher->cipherCtx, ciphertext,
                                   &outLen, plaintext, plaintextLen);

    if (ICC_OSSL_SUCCESS != rc) {
        return FAIL_CIPHER_INTERNAL_ENCRYPTUPDATE;
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
          gslogMessagePrefix("CipherText : ");
          gslogMessageHex((char *)ciphertext, 0, outLen, 0, 0, NULL);
        }
#endif
    }

  return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_encryptUpdate
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1encryptUpdate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId, jbyteArray plaintext,
   jint plaintextOffset, jint plaintextLen, jbyteArray ciphertext, jint ciphertextOffset,
   jboolean needsReinit)
{
  static const char * functionName = "NativeInterface.CIPHER_encryptUpdate";

  ICC_CTX *   ockCtx           = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher        = (OCKCipher *)((intptr_t) ockCipherId);
  unsigned char *      plaintextNative  = NULL;
  unsigned char *      ciphertextNative = NULL;
  int         outLen           = 0;
  int         returnResult     = 0;

  jboolean    isCopy           = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if ((ockCipher == NULL) || (plaintext == NULL) ||(ciphertext == NULL)) {
    throwOCKException(env, 0, "The specified Cipher encrypt update arguments are incorrect.");
    if( debug ) {
      gslogFunctionExit(functionName);
    }
    return (jint) outLen;
  }
  /* Convert the jbytearray plaintext and ciphertext to c array*/
  plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));
  ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));

  if( NULL == ciphertextNative || NULL == plaintextNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
#ifdef DEBUG_CIPHER_DATA
    if( debug ) {
      gslogMessagePrefix("PlainText : ");
      gslogMessageHex((char *) plaintextNative, plaintextOffset, plaintextLen, 0, 0, NULL);
    }
#endif

      returnResult = CIPHER_encryptUpdate_internal(ockCtx, ockCipher, plaintextNative + (int)plaintextOffset, (int)plaintextLen,
                             ciphertextNative + (int)ciphertextOffset, needsReinit);
      if (CIPHER_INTERNAL_SUCCESS > returnResult) {
          ockCheckStatus(ockCtx);
      }
  }

  if( plaintextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
  }

  if( ciphertextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return (jint)returnResult;
}

JNIEXPORT int CIPHER_encryptFinal_internal(ICC_CTX *ockCtx, OCKCipher *ockCipher, unsigned char *plaintext,
                       int plaintextLen, unsigned char *ciphertext, bool needsReinit) {
    int updateOutlen = 0;
    int finalOutlen = 0;
    int outLen = 0;
    int rc = ICC_OSSL_SUCCESS;

    if (needsReinit) {
        if (ockCipher->copy_context == 0) {
            ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx, ockCipher->cached_context);
        } else {
            ICC_EVP_EncryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
        }
    }

    if (plaintextLen > 0) {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("PlainText : ");
            gslogMessageHex((char *)plaintext, 0, plaintextLen, 0, 0, NULL);
        }
#endif

        rc = ICC_EVP_EncryptUpdate(ockCtx, ockCipher->cipherCtx, ciphertext,
                                   &updateOutlen, plaintext, plaintextLen);
        if (ICC_OSSL_SUCCESS != rc) {
            return FAIL_CIPHER_INTERNAL_ENCRYPTUPDATE;
        } else {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessagePrefix("CipherText [update] : ");
                gslogMessageHex((char *)ciphertext, 0, updateOutlen, 0, 0, NULL);
            }
#endif
        }
    }

    rc = ICC_EVP_EncryptFinal(ockCtx, ockCipher->cipherCtx, ciphertext + updateOutlen,
                              &finalOutlen);
    if (ICC_OSSL_SUCCESS != rc) {
        return FAIL_CIPHER_INTERNAL_ENCRYPTFINAL;
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("CipherText [final] : ");
            gslogMessageHex((char *)ciphertext, updateOutlen, finalOutlen, 0, 0, NULL);

            gslogMessagePrefix("CipherText : ");
            gslogMessageHex((char *)ciphertext, 0, updateOutlen + finalOutlen, 0, 0, NULL);
        }
#endif
    }

    outLen = updateOutlen + finalOutlen;
    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_encryptFinal
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1encryptFinal
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId, jbyteArray plaintext,
   jint plaintextOffset, jint plaintextLen, jbyteArray ciphertext, jint ciphertextOffset,
   jboolean needsReinit)
{
  static const char * functionName = "NativeInterface.CIPHER_encryptFinal";

  ICC_CTX *   ockCtx           = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher        = (OCKCipher *)((intptr_t) ockCipherId);
  unsigned char *      plaintextNative  = NULL;
  unsigned char *      ciphertextNative = NULL;
  int         returnResult     = 0;
  jboolean    isCopy           = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ((ockCipher == NULL) || (ciphertext == NULL)) {
  	  throwOCKException(env, 0, "The specified Cipher encrypt final arguments are incorrect.");
  	  if( debug ) {
  	    gslogFunctionExit(functionName);
  	  }
  	  return (jint) returnResult;
  	}
  /* Convert the jbytearray plaintext and ciphertext to c array*/
  if( plaintextLen > 0 ) {
  	plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));
  }
  ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
  if( (NULL == ciphertextNative) || ((plaintextLen > 0) && (plaintextNative == NULL)) ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {

      returnResult = CIPHER_encryptFinal_internal(ockCtx, ockCipher, plaintextNative + (int)plaintextOffset, (int)plaintextLen,
                              ciphertextNative + (int)ciphertextOffset, (bool)needsReinit);
      if (CIPHER_INTERNAL_SUCCESS > returnResult) {
          ockCheckStatus(ockCtx);
      }
  }

  if( plaintextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
  }

  if( ciphertextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return (jint)returnResult;
}


JNIEXPORT int CIPHER_decryptUpdate_internal(ICC_CTX *ockCtx, OCKCipher *ockCipher, unsigned char *ciphertext,
                        int ciphertextLen, unsigned char *plaintext, bool needsReinit) {
    int outLen = 0;

    if (needsReinit) {
        if (ockCipher->copy_context == 0) {
            ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx, ockCipher->cached_context);
        } else {
            ICC_EVP_DecryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
        }
    }

#ifdef DEBUG_CIPHER_DATA
    if (debug) {
        if (ciphertext) {
            gslogMessagePrefix("CipherText : ");
            gslogMessageHex((char *)ciphertext, 0, ciphertextLen, 0, 0, NULL);
        }
    }
#endif

    int rc = ICC_EVP_DecryptUpdate(ockCtx, ockCipher->cipherCtx, plaintext, &outLen,
                                   ciphertext, ciphertextLen);
    if (ICC_OSSL_SUCCESS != rc) {
        return FAIL_CIPHER_INTERNAL_DECRYPTUPDATE;
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("PlainText : ");
            gslogMessageHex((char *)plaintext, 0, outLen, 0, 0, NULL);
        }
#endif
    }

    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_decryptUpdate
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1decryptUpdate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId, jbyteArray ciphertext,
   jint ciphertextOffset, jint ciphertextLen, jbyteArray plaintext, jint plaintextOffset,
   jboolean needsReinit)
{
  static const char * functionName = "NativeInterface.CIPHER_decryptUpdate";

  ICC_CTX *   ockCtx           = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher        = (OCKCipher *)((intptr_t) ockCipherId);
  unsigned char *      plaintextNative  = NULL;
  unsigned char *      ciphertextNative = NULL;
  int         outLen           = 0;
  int         returnResult     = 0;
  jboolean    isCopy           = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if ((ockCipher == NULL) || (ciphertext == NULL) || (plaintext == NULL)) {
  	  throwOCKException(env, 0, "The specified Cipher decrypt update arguments are incorrect.");
  	  if( debug ) {
  	    gslogFunctionExit(functionName);
  	  }
  	  return (jint) outLen;
  	}
  /* Convert the jbytearray plaintext and ciphertext to c array*/
  ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
  plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));

  if( NULL == ciphertextNative || NULL == plaintextNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {

      returnResult = CIPHER_decryptUpdate_internal(ockCtx, ockCipher, ciphertextNative + (int)ciphertextOffset, (int)ciphertextLen,
                             plaintextNative + (int)plaintextOffset, (bool)needsReinit);
      if (CIPHER_INTERNAL_SUCCESS != returnResult) {
          ockCheckStatus(ockCtx);
      }
  }
  if( ciphertextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
  }

  if( plaintextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return (jint)returnResult;
}


JNIEXPORT int CIPHER_decryptFinal_internal(ICC_CTX *ockCtx, OCKCipher *ockCipher, unsigned char *ciphertext, int ciphertextLen,
                       unsigned char *plaintext, bool needsReinit) {
    int rc = ICC_OSSL_SUCCESS;
    int updateOutlen = 0;
    int finalOutlen = 0;
    int outLen = 0;

    if (needsReinit) {
        if (ockCipher->copy_context == 0) {
            ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx, ockCipher->cached_context);
        } else {
            ICC_EVP_DecryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
        }
    }

    if (ciphertextLen > 0) {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("CipherText : ");
            gslogMessageHex((char *)ciphertext, 0, ciphertextLen, 0, 0, NULL);
        }
#endif

        rc = ICC_EVP_DecryptUpdate(ockCtx, ockCipher->cipherCtx, plaintext,
                                   &updateOutlen, ciphertext, ciphertextLen);
        if (ICC_OSSL_SUCCESS != rc) {
            return FAIL_CIPHER_INTERNAL_DECRYPTUPDATE;
        }
        else {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessagePrefix("PlainText [update] : ");
                gslogMessageHex((char *)plaintext, 0, updateOutlen, 0, 0, NULL);
            }
#endif
        }
    }

    rc = ICC_EVP_DecryptFinal(ockCtx, ockCipher->cipherCtx, plaintext + updateOutlen,
                              &finalOutlen);
    if (ICC_OSSL_SUCCESS != rc) {
        unsigned long errCode = ICC_ERR_peek_last_error(ockCtx);
        const char* errStr = ICC_ERR_reason_error_string(ockCtx, errCode);
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
        if ((0 == strcmp(errStr, "bad decrypt"))) {
            return FAIL_CIPHER_INTERNAL_DECRYPTFINAL_BAD_PADDING_ERROR;
        }
#ifdef __MVS__
  #pragma convert(pop)
#endif
        return FAIL_CIPHER_INTERNAL_DECRYPTFINAL;
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("PlainText [final] : ");
            gslogMessageHex((char *)plaintext, updateOutlen, finalOutlen, 0, 0, NULL);

            gslogMessagePrefix("PlainText : ");
            gslogMessageHex((char *)plaintext, 0, updateOutlen + finalOutlen, 0, 0, NULL);
        }
#endif
    }

    outLen = updateOutlen + finalOutlen;
    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_decryptFinal
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1decryptFinal
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId, jbyteArray ciphertext,
 jint ciphertextOffset, jint ciphertextLen, jbyteArray plaintext, jint plaintextOffset,
   jboolean needsReinit)
{
  static const char * functionName = "NativeInterface.CIPHER_decryptFinal";

  ICC_CTX *   ockCtx           = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher        = (OCKCipher *)((intptr_t) ockCipherId);
  unsigned char *      plaintextNative  = NULL;
  unsigned char *      ciphertextNative = NULL;

  int        returnResult      = 0;
  jboolean   isCopy            = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if ((ockCipher == NULL) || ( plaintext == NULL)) {
    throwOCKException(env, 0, "The specified Cipher decrypt final arguments are incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return (jint) returnResult;
  }
  /* Convert the jbytearray plaintext and ciphertext to c array*/
  if( ciphertextLen > 0 ) {
    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext,  &isCopy));
  }
  plaintextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));
  if( (NULL == plaintextNative) || ((ciphertextLen > 0) && (ciphertextNative == NULL)) ) {
      throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {

      returnResult = CIPHER_decryptFinal_internal(ockCtx, ockCipher, ciphertextNative + (int)ciphertextOffset, (int)ciphertextLen,
                              plaintextNative + (int)plaintextOffset, (bool)needsReinit);

      if (CIPHER_INTERNAL_SUCCESS > returnResult) {
          ockCheckStatus(ockCtx);
      }
    }
  if( ciphertextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
  }

  if( plaintextNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    checkHardwareSupport
 * Signature: (JJI[B[B)I
 */
FUNC *JCC_OS_helpers(ICC_CTX *ctx);
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_checkHardwareSupport(JNIEnv *env, jclass thisObj, jlong ockContextId) {
        int rv = 0;
	ICC_CTX *ctx = (ICC_CTX *)((intptr_t) ockContextId);

  static const char * functionName = "NativeInterface.checkHardwareSupport";


  FUNC* funcPtr = ICC_OS_helpers(ctx);

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if( debug ) {
    gslogMessage("funcPtr=%lx", funcPtr);
  }
  if(NULL == funcPtr) {
    /* printf ("funcPtr is null \n"); */
    if( debug ) {
     gslogMessage("funcPtr=%lx", funcPtr);
     gslogFunctionExit(functionName);
    }
    return -1;
  }
  if ((NULL == funcPtr[0].func) || (NULL == funcPtr[0].name)) {
     if( debug ) {
       gslogMessage ("funcPtr[0] is null or funcPtr[0].name is null"); 
       gslogFunctionExit(functionName);
     }
     return -1;
  }
  else
  {
     if( debug ) {
       gslogMessage ("funcPtr[0].func is '0x%p' funcPtr[0].name is '%s'", funcPtr[0].func, funcPtr[0].name); 
     }
  }
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
  if (0 != strcmp("presence", funcPtr[0].name)) {
#ifdef __MVS__
  #pragma convert(pop)
#endif
     if( debug ) {
       gslogMessage ("Function mismatch, expected presence  did not get it got %s", funcPtr[0].name);
       gslogFunctionExit(functionName);
     }
    return -1;
  }
  if( debug ) {
       gslogMessage ("calling funcPtr[0] and check for rv presence functions \n"); 
  }
  rv  = (*funcPtr[0].func)(); /* Call presence function and check rv (42) */
  /* came from OCK sample code - that is why magic number is hard coded. */
  if (42 != rv) {
    if( debug ) {
       gslogMessage ("presence function did not return expected 42 got %d\n", rv); 
       gslogFunctionExit(functionName);
     }
    return -1;
  }
  else {
    if( debug ) {
       gslogMessage ("presence function returned 42 \n"); 
    }
  }
  if ((NULL == funcPtr[1].func) || (NULL == funcPtr[1].name)) {
    if( debug ) {
       gslogMessage ("funcPtr[1] func is null or funcPtr[1].name is null");
       gslogFunctionExit(functionName);
     }
    return -1;
  }
  
  if ((NULL == funcPtr[2].func) || (NULL == funcPtr[2].name)) {
    if( debug ) {
       gslogMessage ("funcPtr[2] func is null or funcPtr[2].name is null"); 
       gslogFunctionExit(functionName);
     }
    return -1;
  }
  
  KMC = (KMC_FuncPtr)funcPtr[2].func; // z_kmc_native
  if( debug ) {
    gslogMessage ("KMC %s", funcPtr[2].name); 
    gslogFunctionExit(functionName);
  }
  return 1;
  
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CIPHER_1delete
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId)
{
  static const char * functionName = "NativeInterface.CIPHER_delete";

  ICC_CTX *   ockCtx    = (ICC_CTX *)((intptr_t) ockContextId);
  OCKCipher * ockCipher = (OCKCipher *)((intptr_t) ockCipherId);
  int         rc        = ICC_OSSL_SUCCESS;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (ockCipher == NULL) {
    //Nothing to do
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return;
  }

  if (ockCipher->cipherCtx != NULL) {
    rc = ICC_EVP_CIPHER_CTX_free(ockCtx, ockCipher->cipherCtx);
    ockCipher->cipherCtx = NULL;
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_free failed!\n");
    }
  }

  if (ockCipher->copy_context == 0 && ockCipher->cached_context != NULL) {
    ICC_EVP_CIPHER_CTX_free(ockCtx, ockCipher->cached_context);
    ockCipher->cached_context = NULL;
  }
  FREE_N_NULL(ockCipher);
  if( debug ) {
    gslogFunctionExit(functionName);
  }
}

