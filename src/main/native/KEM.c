/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>
<<<<<<< HEAD
=======
#include <string.h>
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    KEM_encapsulate
<<<<<<< HEAD
 * Signature: (JI)J
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1encapsulate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId, jbyteArray wrappedKey, jbyteArray randomKey)
{
  static const char * functionName = "NativeInterface.KEM_encapsulate";

  ICC_CTX *         ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY_CTX* evp_pk;
  ICC_EVP_PKEY*     pa = (ICC_EVP_PKEY *) ((intptr_t) ockPKeyId);
  jlong             mlkeyId = 0;
  size_t            wrappedkeylen = 0;
  size_t            genkeylen = 0;
  jboolean          isCopy = 0;
  unsigned char *   wrappedKeyLocal = NULL;
  unsigned char *   genkeylocal = NULL;
  unsigned char *   wrappedKeyNative = NULL;
  unsigned char *   genKeyNative = NULL;

  evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
  if (!evp_pk) {
    throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
    return;
  }
  
  int rc = -1;

  rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
  if (rc != ICC_OSSL_SUCCESS) {
    throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate_init failed");
    return;
  }

  rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL, &genkeylen);
  if (rc != ICC_OSSL_SUCCESS) {
    throwOCKException(env, 0,"ICC_EVP_PKEY_encapsulate failed getting lenghts");
    return;
  }  

  wrappedKeyLocal = (unsigned char *)malloc(wrappedkeylen);
  genkeylocal = (unsigned char *)malloc(genkeylen);
  if (wrappedKeyLocal == NULL || genkeylocal == NULL) {
    if (wrappedKeyLocal != NULL){
      free(wrappedKeyLocal);
    }
    if (genkeylocal != NULL){
      free(wrappedKeyLocal);
    }  
    throwOCKException(env, 0, "malloc failed");
  } else {

    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedKeyLocal, &wrappedkeylen, genkeylocal, &genkeylen);

    if (rc != ICC_OSSL_SUCCESS) {
      throwOCKException(env, 0,"ICC_EVP_PKEY_encapsulate failed");
      return;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, wrappedKey, NULL);   
    memcpy(bytes, wrappedKeyLocal, wrappedkeylen);
    (*env)->ReleaseByteArrayElements(env, wrappedKey, bytes, 0);

    bytes = (*env)->GetByteArrayElements(env, randomKey, NULL);
    memcpy(bytes, genkeylocal, genkeylen);
    (*env)->ReleaseByteArrayElements(env, randomKey, bytes, 0);

  }  

=======
 * Signature: (JJ[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1encapsulate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray wrappedKey, jbyteArray randomKey) {

    ICC_CTX          *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY_CTX *evp_pk           = NULL;
    ICC_EVP_PKEY     *pa               = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    size_t            wrappedkeylen    = 0;
    size_t            genkeylen        = 0;
    unsigned char    *wrappedKeyLocal  = NULL;
    unsigned char    *genkeylocal      = NULL;
 
    evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
    if (!evp_pk) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return;
    }

    int rc = -1;

    rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate_init failed");
        return;
    }

    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL,
                                  &genkeylen);
    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_encapsulate failed getting lengths");
        return;
    }

    wrappedKeyLocal = (unsigned char *)malloc(wrappedkeylen);
    genkeylocal     = (unsigned char *)malloc(genkeylen);
    if (wrappedKeyLocal == NULL || genkeylocal == NULL) {
        if (wrappedKeyLocal != NULL) {
            free(wrappedKeyLocal);
        }
        if (genkeylocal != NULL) {
            free(wrappedKeyLocal);
        }
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "malloc failed");
        return;
    } else {
        rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedKeyLocal,
                                      &wrappedkeylen, genkeylocal, &genkeylen);

        if (rc != ICC_OSSL_SUCCESS) {
            if (wrappedKeyLocal != NULL) {
                free(wrappedKeyLocal);
            }
            if (genkeylocal != NULL) {
                free(wrappedKeyLocal);
            }
            ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
            throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate failed");
            return;
        }

        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);

        jbyte *bytes = (*env)->GetByteArrayElements(env, wrappedKey, NULL);
        memcpy(bytes, wrappedKeyLocal, wrappedkeylen);
        (*env)->ReleaseByteArrayElements(env, wrappedKey, bytes, 0);

        bytes = (*env)->GetByteArrayElements(env, randomKey, NULL);
        memcpy(bytes, genkeylocal, genkeylen);
        (*env)->ReleaseByteArrayElements(env, randomKey, bytes, 0);
    }
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_decapsulate
<<<<<<< HEAD
 * Signature: (J[B)J
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1decapsulate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId, jbyteArray wrappedKey)
{
  static const char * functionName = "NativeInterface.KEM_decapsulate";

  ICC_CTX *                ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY *           ockPKey = (ICC_EVP_PKEY *) ((intptr_t) ockPKeyId);
  ICC_EVP_PKEY_CTX*        evp_pk;
  ICC_EVP_PKEY*            priv = NULL;
  ICC_PKCS8_PRIV_KEY_INFO* p8 = NULL;
  int                      rc = -1;
  jboolean                 isCopy = 0;
  jbyteArray               randomKey;
  jbyteArray               retRndKeyBytes = NULL;
  size_t                   wrappedkeylen = 0;
  size_t                   genkeylen = 0;
  unsigned char *          wrappedKeyNative = NULL;
  unsigned char *          genkeylocal = NULL;
  unsigned char *          genKeyNative = NULL;

  evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
  if (!evp_pk) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
    return retRndKeyBytes;
  }

  rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);

  if (rc != ICC_OSSL_SUCCESS) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate_init failed");
    return retRndKeyBytes;
  }
  wrappedKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, wrappedKey, &isCopy));
  
  if( NULL == wrappedKeyNative ) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    return retRndKeyBytes;
  }

  wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

  rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, NULL, &genkeylen, NULL, wrappedkeylen);

  if (rc != ICC_OSSL_SUCCESS) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative, 0);
    throwOCKException(env, 0, "ICC_EVP_PKEY_deccapsulate to get lenghts failed");
    return retRndKeyBytes;
  }  

  genkeylocal = (unsigned char *)malloc(genkeylen);
  if (genkeylocal == NULL) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "malloc failed");
  } else {
    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genkeylocal, &genkeylen, wrappedKeyNative, wrappedkeylen);

    if (rc != ICC_OSSL_SUCCESS) {
      ICC_EVP_PKEY_free(ockCtx, priv);
      free (genkeylocal);
      (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative, 0);
      throwOCKException(env, 0, "ICC_EVP_PKEY_deccapsulate failed");
      return retRndKeyBytes;
    }

    randomKey = (*env)->NewByteArray(env, genkeylen);

    if( randomKey == NULL ) {
      throwOCKException(env, 0, "NewByteArray failed");
    } else {
      genKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, randomKey, &isCopy));

      if( genKeyNative == NULL ) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } else {
        memcpy(genKeyNative, genkeylocal, genkeylen);
        retRndKeyBytes = randomKey;
      }
    }
  }

  if (genKeyNative != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative, 0);
  }   

  if (wrappedKeyNative != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative, 0);
  }  

  ICC_EVP_PKEY_free(ockCtx, priv);

  return retRndKeyBytes;
=======
 * Signature: (JJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1decapsulate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray wrappedKey) {

    ICC_CTX                 *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY            *ockPKey   = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    ICC_EVP_PKEY_CTX        *evp_pk    = NULL;
    int                      rc        = -1;
    jboolean                 isCopy    = 0;
    jbyteArray               randomKey = NULL;
    jbyteArray               retRndKeyBytes   = NULL;
    size_t                   wrappedkeylen    = 0;
    size_t                   genkeylen        = 0;
    unsigned char           *wrappedKeyNative = NULL;
    unsigned char           *genkeylocal      = NULL;
    unsigned char           *genKeyNative     = NULL;

    evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
    if (!evp_pk) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return retRndKeyBytes;
    }

    rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);

    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate_init failed");
        return retRndKeyBytes;
    }
    wrappedKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, wrappedKey, &isCopy));

    if (NULL == wrappedKeyNative) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
        return retRndKeyBytes;
    }

    wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, NULL, &genkeylen, NULL,
                                  wrappedkeylen);

    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                              JNI_ABORT);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_deccapsulate to get lenghts failed");
        return retRndKeyBytes;
    }

    genkeylocal = (unsigned char *)malloc(genkeylen);
    if (genkeylocal == NULL) {
        throwOCKException(env, 0, "malloc failed");
    } else {
        rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genkeylocal, &genkeylen,
                                      wrappedKeyNative, wrappedkeylen);

        if (rc != ICC_OSSL_SUCCESS) {
            ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
            free(genkeylocal);
            (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                                  wrappedKeyNative, JNI_ABORT);
            throwOCKException(env, 0, "ICC_EVP_PKEY_deccapsulate failed");
            return retRndKeyBytes;
        }

        randomKey = (*env)->NewByteArray(env, genkeylen);

        if (randomKey == NULL) {
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                env, randomKey, &isCopy));

            if (genKeyNative == NULL) {
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                memcpy(genKeyNative, genkeylocal, genkeylen);
                retRndKeyBytes = randomKey;
            }
        }
    }

    if (genKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative, 0);
    }

    if (wrappedKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                              JNI_ABORT);
    }

    ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);

    return retRndKeyBytes;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
}
