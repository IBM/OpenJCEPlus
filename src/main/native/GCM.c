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
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>
#include <iccglobals.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Padding.h"
#include "Utils.h"
#include "zHardwareFunctions.h"

#define ICC_AES_GCM_CTX_NEW_FAILED 1
#define ICC_AES_GCM_INIT_FAILED 2
#define ICC_AES_GCM_CRYPTUPDATE_FAILED 3
#define ICC_AES_GCM_CRYPTFINAL_FAILED 4
#define GetPRIMITICEARRAYCRITICAL 5
#define ICC_AES_GCM_TAG_MISMATCH 6

#ifdef WINDOWS
#define THREAD_LOCAL __declspec( thread )
#else
#define THREAD_LOCAL __thread
#endif

// Pointers of functions that are only available on some hardware (might be null)
ECB_FuncPtr ECB;     // equivalent to s390_km_native
GHASH_FuncPtr GHASH; // equivalent to s390_kimd_native
zS390_FuncPtr zS390; // equivalent to s390_kmgcm_native

ICC_AES_GCM_CTX* getOrfreeGCMContext(ICC_CTX* ockCtx, int keyLen) {
#if !defined(AIX) && !defined(__MVS__)
    static THREAD_LOCAL ICC_AES_GCM_CTX* gcmCtx16 = NULL;
    static THREAD_LOCAL ICC_AES_GCM_CTX* gcmCtx24 = NULL;
    static THREAD_LOCAL ICC_AES_GCM_CTX* gcmCtx32 = NULL;
    static THREAD_LOCAL ICC_AES_GCM_CTX* FIPSgcmCtx16 = NULL;
    static THREAD_LOCAL ICC_AES_GCM_CTX* FIPSgcmCtx24 = NULL;
    static THREAD_LOCAL ICC_AES_GCM_CTX* FIPSgcmCtx32 = NULL;
    static THREAD_LOCAL ICC_CTX* FIPSContext = NULL;
    static THREAD_LOCAL ICC_CTX* context = NULL;
    ICC_AES_GCM_CTX* gcmCtx = NULL;
    ICC_AES_GCM_CTX** gcmCtxPointer = NULL;
    int isFips = 0;
    int rc = 0;
    if (keyLen > 0 ) {
        if (ockCtx == context)
            isFips = 0;
        else if (ockCtx == FIPSContext)
            isFips = 1;
        else if (context == NULL || FIPSContext == NULL) {
            ICC_STATUS status;
            if (ICC_GetStatus(ockCtx, &status) != ICC_OSSL_SUCCESS)
                return NULL;
            isFips = status.mode;
            if (isFips == 0 && context == NULL)
                context = ockCtx;
            else if (isFips == 1 && FIPSContext == NULL)
                FIPSContext = ockCtx;
            else
                return NULL;
        }

        if (isFips == 0)
            gcmCtxPointer = (keyLen == 16 ? &gcmCtx16 : (keyLen == 24 ? &gcmCtx24 : &gcmCtx32));
        else
            gcmCtxPointer = (keyLen == 16 ? &FIPSgcmCtx16 : (keyLen == 24 ? &FIPSgcmCtx24 : &FIPSgcmCtx32));

        if (*gcmCtxPointer == NULL) {
            *gcmCtxPointer = ICC_AES_GCM_CTX_new(ockCtx);
            rc = ICC_AES_GCM_CTX_ctrl(ockCtx, *gcmCtxPointer, ICC_AES_GCM_CTRL_TLS13, 0, NULL);
            if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("ICC_AES_GCM_CTX_ctrl failed rc = %d\n", rc);
                }
#endif
                if (*gcmCtxPointer != NULL) {
                    ICC_AES_GCM_CTX_free (ockCtx, *gcmCtxPointer);
                }
                return NULL;
            }
        }
        gcmCtx = *gcmCtxPointer;
        return gcmCtx;
    } else {
        if (gcmCtx16 != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, gcmCtx16);
            gcmCtx16=NULL;
        } else if (gcmCtx24 != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, gcmCtx24);
            gcmCtx24=NULL;
        } else if (gcmCtx32 != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, gcmCtx32);
             gcmCtx32=NULL;
        } else if (FIPSgcmCtx16 != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, FIPSgcmCtx16);
            FIPSgcmCtx16=NULL;
        } else if (FIPSgcmCtx24 != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, FIPSgcmCtx24);
            FIPSgcmCtx24=NULL;
        } else if (FIPSgcmCtx32 != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, FIPSgcmCtx32);
            FIPSgcmCtx32=NULL;
        }
         gcmCtxPointer = NULL;
         gcmCtx = NULL;
        return NULL;
    }
#endif
}

/*============================================================================
*
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_InitForUpdateDecrypt_core
* Signature: (JJ)V
*/
int GCM_InitForUpdateDecrypt_core(JNIEnv *env, ICC_CTX *ockCtx, ICC_AES_GCM_CTX *gcmCtx,
    unsigned char *key, int keyLen,
    unsigned char *iv,  int ivLen,
    unsigned char *aad, int aadLen, unsigned long *updateOutlen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
     long unsigned updateAADlen   = 0;
     /* long unsigned finalOutlen    = 0; */
    int           rc             = ICC_OSSL_SUCCESS;

    static const char *functionName = "NativeInterface.GCM_InitForUpdateDecrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

    if (gcmCtx == 0) {
        gcmCtx = getOrfreeGCMContext(ockCtx, keyLen);
    }
    rc = gcmCtx != NULL ? ICC_OSSL_SUCCESS : ICC_OSSL_FAILURE;

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI GCM_InitForUpdateDecrypt_core gcmCtx %ld keyLen %d ivLen %d aadLen %d updateOutlen %ld\n", gcmCtx, keyLen, ivLen, aadLen,  *updateOutlen);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
        // Need to Initialize

 #ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM NI calling ICC_AES_GCM_iNIt\n");
        }
#endif
        rc = ICC_AES_GCM_Init(ockCtx, gcmCtx, iv, ivLen, key, keyLen);

        if (rc == ICC_OSSL_SUCCESS) {
            if (aadLen > 0) {
                /* AAD */
#ifdef DEBUG_GCM_DETAIL
                   if ( debug ) {
                    gslogMessage ("DETAIL_GCM NI calling ICC_AES_GCM_DecryptUpdate for AAD\n");
                }
#endif
                rc = ICC_AES_GCM_DecryptUpdate(ockCtx, gcmCtx,aad, aadLen,NULL, 0,NULL, &updateAADlen);

                if ( rc != ICC_OSSL_SUCCESS ) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
                    if ( debug ) {
                        gslogMessage ("NI data ICC_AES_GCM_DecryptUpdate ICC_AES_GCM_CRYPTUPDATE_FAILED\n" );
                    }
#endif
                    return ICC_AES_GCM_CRYPTUPDATE_FAILED;
                } else {
#ifdef DEBUG_GCM_DETAIL
                       if ( debug ) {
                        gslogMessage ("DETAIL_GCM NI AAD ICC_AES_GCM_DecryptUpdate Succeeded\n");
                    }
#endif
                }
             } else {

#ifdef DEBUG_GCM_DETAIL
                   if ( debug ) {
                    gslogMessage ("DETAIL_GCM NI No AAD ICC_AES_GCM_DecryptUpdate not called \n");
                }
#endif
            }

        } else {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
               if ( debug ) {
                gslogMessage ("DETAIL_GCM NI ICC_AES_GCM_DecryptUpdate ICC_AES_GCM_INIT_FAILED \n");
            }
#endif
            return ICC_AES_GCM_INIT_FAILED;
        }
    } else {
        /* GCM CTX Failed - no need to free it. */
        ockCheckStatus(ockCtx);

#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM NI gslogMessage ICC_AES_GCM_NEW_FAILED\n" );
        }
#endif
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }
    return 0;
#else
    return -1;
#endif
}

/*============================================================================
*
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_UpdForUpdateDecrypt_core
* Signature:
*/
int GCM_UpdForUpdateDecrypt_core(JNIEnv *env, ICC_CTX *ockCtx, ICC_AES_GCM_CTX *gcmCtx,
    unsigned char *data, int dataOffset, int dataLen,
    unsigned char *out, int outOffset,
    unsigned long *updateOutlen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    /* long unsigned updateAADlen   = 0; */
    /* long unsigned finalOutlen    = 0;*/
    int           rc             = ICC_OSSL_SUCCESS;

    static const char *functionName = "NativeInterface.GCM_UpdForUpdateDecrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }
    *updateOutlen = 0;

    if (gcmCtx == 0) {
        rc = ICC_OSSL_FAILURE;
    } else {
        rc = ICC_OSSL_SUCCESS;
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI GCM_UpdForUpdateDecrypt_core gcmCtx %ld  dataOffset %d dataLen %d outOffset %d updateOutlen %ld\n", gcmCtx,
            dataOffset, dataLen, outOffset, *updateOutlen);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {

#ifdef DEBUG_GCM_DETAIL
               if ( debug ) {
                gslogMessage ("DETAIL_GCM NI checking for data > 0\n");
            }
#endif
        if (dataLen > 0) {

#ifdef DEBUG_GCM_DETAIL
               if ( debug ) {
                gslogMessage ("DETAIL_GCM NI ICC_AES_GCM_DecryptUpdate dataLen > 0 dataLen = %d outOffset %d updateOutlen %ld\n",
                dataLen, dataOffset, *updateOutlen);
            }
#endif
            rc = ICC_AES_GCM_DecryptUpdate(ockCtx, gcmCtx,NULL, 0,data + dataOffset, dataLen, out + outOffset, updateOutlen);

#ifdef DEBUG_GCM_DETAIL
               if ( debug ) {
                gslogMessage ("DETAIL_GCM NI data update returned ICC_AES_GCM_DecryptUpdate returns rc = %d updateOutLen = %ld\n", rc, *updateOutlen);

            }
#endif
            // that needs to catch a hash mismatch condition
            if ( rc != ICC_OSSL_SUCCESS ) {
                ockCheckStatus(ockCtx);
                return ICC_AES_GCM_CRYPTUPDATE_FAILED;
            } else {

#ifdef DEBUG_GCM_DETAIL
                   if ( debug ) {
                    gslogMessage ("DETAIL_GCM NI data ICC_AES_GCM_DecryptUpdate Succeeded\n");
                }
#endif
            }
        } else {
#ifdef DEBUG_GCM_DETAIL
               if ( debug ) {
                gslogMessage ("DETAIL_GCM NI  No data to process\n");
            }
#endif
        }
    } else {
        /* GCM CTX Failed - no need to free it. */
        ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
           if ( debug ) {
            gslogMessage ("DETAIL_GCM NI  ICC_AES_GCM_DecryptUpdate ICC_AES_GCM_NEW_FAILED\n" );
        }
#endif
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }
    return 0;

#else
    return -1;
#endif
}

/*============================================================================
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_InitForUpdateEncrypt_core
* Signature:
*/
int GCM_InitForUpdateEncrypt_core(JNIEnv* env, ICC_CTX* ockCtx, ICC_AES_GCM_CTX* gcmCtx,
    unsigned char* key   , int keyLen,
    unsigned char* iv    , int ivLen,
    unsigned char* aad   , int aadLen,
    unsigned long *updateOutlen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    unsigned char * keyNative        = key;
    unsigned char * ivNative         = iv;
    unsigned char *          aadNative        = aad;
    unsigned long   updateAADlen     = 0;
    /* long unsigned   finalOutlen      = 0;*/
    int             rc               = ICC_OSSL_SUCCESS;
    /* jboolean        isCopy           = 0; */
    static const char * functionName = "NativeInterface.GCM_InitForUpdateEncrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DATA
    if ( debug ) {
        gslogMessagePrefix ("DATA_GCM iv : ");
        gslogMessageHex ((char*) iv, 0, (int) ivLen, 0, 0, NULL);

        gslogMessagePrefix ("DATA_GCM key : ");
        gslogMessageHex ((char*) key, 0, (int) keyLen, 0, 0, NULL);


        gslogMessagePrefix ("DATA_GCM aad : ");
        gslogMessageHex ((char*) aad, 0, (int) aadLen, 0, 0, NULL);
    }
#endif
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI GCM_InitForUpdateEncrypt_core updateOutlen %ld\n", *updateOutlen);
        gslogMessage ("DETAIL_GCM N NI first update calling getOrfreeGCMCtx\n");
    }
#endif
    if (gcmCtx == 0) {
        gcmCtx = getOrfreeGCMContext(ockCtx, keyLen);
    }
    rc = gcmCtx != NULL ? ICC_OSSL_SUCCESS : ICC_OSSL_FAILURE;
#ifdef DEBUG_GCM_DETAIL
       if ( debug ) {
        gslogMessage ("NI first update rc from getOrfreeGCMCtx %d\n", rc);
         gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_CTX_new %d gcmCtx=%x", (int) rc, gcmCtx);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
        //Do initialization
        rc = ICC_AES_GCM_Init(ockCtx, gcmCtx, ivNative, ivLen, keyNative, keyLen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_iNIt %d", (int) rc);
        }
#endif
        if (rc == ICC_OSSL_SUCCESS) {
            if (aadLen > 0) {
                // update AAD

#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("DETAIL_GCM rc  ICC_AES_GCM_EncryptUpdateCalled with AADLen %d\n", aadLen);
                }
#endif

                rc = ICC_AES_GCM_EncryptUpdate(ockCtx, gcmCtx,
                    aadNative, aadLen,
                    NULL, 0,
                    NULL, &updateAADlen);
#ifdef DEBUG_GCM_DETAIL
               if ( debug ) {
                   gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_EncryptUpdate(aadLen > 0) %d updateAADlen %d", (int) rc, updateAADlen);
               }
#endif
                if (rc != ICC_OSSL_SUCCESS) {
                    ockCheckStatus(ockCtx);
                    return ICC_AES_GCM_CRYPTUPDATE_FAILED;
                } else {
#ifdef DEBUG_GCM_DETAIL
                    if ( debug ) {
                        gslogMessage ("DETAIL_GCM ICC_AES_GCM_EncryptUpdate call for AAD succeded\n");
                    }
#endif
                }
            } else {
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("DETAIL_GCM rc  ICC_AES_GCM_EncryptUpdate not called for AAD\n");
                }
#endif
            }

        } else {
            ockCheckStatus(ockCtx);
            return ICC_AES_GCM_INIT_FAILED;
        }
    } else {
        ockCheckStatus(ockCtx);
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }
    return 0;
#else
    return -1;
#endif
}

/*============================================================================
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_UpdForUpdateEncrypt_core
* Signature:
*/
int GCM_UpdForUpdateEncrypt_core(JNIEnv* env, ICC_CTX* ockCtx, ICC_AES_GCM_CTX* gcmCtx,
    unsigned char* data , int dataLen, int dataOffset,
    unsigned char* out, int outOffset, unsigned long* updateOutlen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    /* unsigned long   updateAADlen     = 0; */
    /*long unsigned   finalOutlen      = 0;*/
    int             rc               = ICC_OSSL_SUCCESS;
    /* jboolean        isCopy           = 0; */
    static const char * functionName = "NativeInterface.GCM_UpdForUpdateEncrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DATA
    if ( debug ) {
        gslogMessagePrefix ("DATA_GCM data : ");
        gslogMessageHex ((char*) data, 0, (int) dataLen, 0, 0, NULL);

//        gslogMessagePrefix ("DATA_GCM aadNative : ");
//        gslogMessageHex (aadNative, 0, (int) aadLen, 0, 0, NULL);
    }
#endif
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("NI GCM_UpdForUpdateEncrypt_core updateOutlen %ld\n", *updateOutlen);
    }
#endif
    //GCM Ctx cannot be null for subsequent updates
    if (gcmCtx == 0) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI gcmCtx cannot be null\n");
        }
#endif
    }
    rc = ((gcmCtx == 0) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS);

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_CTX_new %d gcmCtx=%x", (int) rc, gcmCtx);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
        if (dataLen > 0) {
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("NI ICC_AES_GCM_EncryptUpdateCalled with data %d\n", dataLen);
            }
#endif
            // update data
            rc = ICC_AES_GCM_EncryptUpdate(ockCtx, gcmCtx,
                         NULL, 0,
                           data + dataOffset, dataLen,
                        out + outOffset, updateOutlen);
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                   gslogMessage ("NI GCM_UpdForUpdateEncrypt_core dataLen > 0 path after ICC_AES_GCM_EncryptUpdate rc %d updateOutlen %ld\n", rc, *updateOutlen);
                gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_EncryptUpdate(plaintextLen > 0) %d updateOutlen %d", (int) rc, *updateOutlen);
            }
#endif
            if (rc != ICC_OSSL_SUCCESS) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("NI ICC_AES_GCM_CRYPTUPDATE_FAILED\n");
                }
#endif
                return ICC_AES_GCM_CRYPTUPDATE_FAILED;
            }
        }
    } else {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI ICC_AES_GCM_CTX_NEW_FAILED\n");
        }
#endif
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }
    return 0;
#else
    return -1;
#endif
}

/*============================================================================
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_FinalForUpdateDecrypt_core
* Signature:
*/
int GCM_FinalForUpdateDecrypt_core(JNIEnv *env, ICC_CTX *ockCtx, ICC_AES_GCM_CTX *gcmCtx,
    unsigned char *data, int dataOffset, int dataLen,
    unsigned char *out, int outOffset,
    int tagLen, unsigned long updateOutlen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)

    /* long unsigned updateAADlen   = 0;*/
    long unsigned finalOutlen    = 0;
    int           rc             = ICC_OSSL_SUCCESS;
    static const char *functionName = "NativeInterface.GCM_FinalForUpdateDecrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("NI NativeInterface GCM_FinalForUpdateDecrypt_core gcmCtx = %ld dataOffset %d dataLen %d outOffset %d tagLen %d updateOutlen %ld\n",
            gcmCtx, dataOffset, dataLen, outOffset, tagLen, updateOutlen);
    }
#endif
    if (gcmCtx == 0) {
        rc = ICC_OSSL_FAILURE;
    } else {
        rc = ICC_OSSL_SUCCESS;
    }
    if ( rc == ICC_OSSL_SUCCESS ) {
        if (dataLen > 0) {
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("NI calling ICC_AES_GCM_DecryptUpdate  dataOffset %d dataLen %d outputOffset %d updateOutlen %ld\n",
                      dataOffset, dataLen, outOffset, updateOutlen);
              }
#endif
                  if ((dataLen - tagLen) > 0) {
                    rc = ICC_AES_GCM_DecryptUpdate(ockCtx, gcmCtx,NULL, 0, data + dataOffset, dataLen - tagLen, out + outOffset, &updateOutlen);
                }

            // that needs to catch a hash mismatch condition
            if ( rc == ICC_OSSL_SUCCESS ) {
                /* obtain up to last block of plaintext and provide tag to compare */
                //rc = ICC_AES_GCM_DecryptFinal(ockCtx, gcmCtx, out + outOffset + updateOutlen, &finalOutlen,data + dataOffset + dataLen, tagLen);
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("NI calling ICC_AES_GCM_DecryptFinal updateOutlen %ld\n", updateOutlen);
                }
#endif
                rc = ICC_AES_GCM_DecryptFinal(ockCtx, gcmCtx, out + outOffset  + updateOutlen, &finalOutlen,  data + dataOffset  + dataLen - tagLen, tagLen);
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("NI ICC_AES_GCM_DecryptFinal returns rc %d finalOutlen %d\n", rc, finalOutlen);
                }
#endif
                if (rc != ICC_OSSL_SUCCESS ) {
                    // entered an error condition here
#ifdef DEBUG_GCM_DETAIL
                    if ( debug ) {
                        gslogMessage ("NI ICC_AES_GCM_DecryptFinal has encountered error condition\n");
                    }
#endif
                    if (rc == -1 ) {
                        // hash mismatch error
                        ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
                        if ( debug ) {
                            gslogMessage ("NI ICC_AES_GCM_DecryptFinal returning ICC_AES_GCM_TAG_MISMATCH\n");
                        }
#endif
                        return ICC_AES_GCM_TAG_MISMATCH;
                    } else {
                        // generic error condition
                        ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
                        if ( debug ) {
                            gslogMessage ("NI ICC_AES_GCM_DecryptFinal returning ICC_AES_GCM_CRYPTFINAL_FAILED\n");
                        }
#endif
                        return ICC_AES_GCM_CRYPTFINAL_FAILED;
                    }
                } else {
#ifdef DEBUG_GCM_DETAIL
                    if ( debug ) {
                        gslogMessage ("NI ICC_AES_GCM_DecryptFInal was successful\n");
                    }
#endif
                }
            } else {

                ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                    gslogMessage ("NI ICC_AES_GCM_DecryptFinal returning ICC_AES_GCM_CRYPTUPDATE_FAILED\n");
                }
#endif
                return ICC_AES_GCM_CRYPTUPDATE_FAILED;
            }
        } else {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("NI ICC_AES_GCM_DecryptUpdate returning ICC_AES_GCM_CTX_NEW_FAILED\n");
            }
#endif
            return ICC_AES_GCM_CTX_NEW_FAILED;
        }
    }
    return 0;
#else
    return -1;
#endif
}

/*============================================================================
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_FinalForUpdateEncrypt_core
* Signature:
*/
int GCM_FinalForUpdateEncrypt_core(JNIEnv* env, ICC_CTX* ockCtx, ICC_AES_GCM_CTX* gcmCtx,
    unsigned char* tag   , int tagLen,
    unsigned char *dataText, int dataOffset, int dataLen,
    unsigned char* out, int outOffset, unsigned long updateOutlen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    unsigned char * outNative = 	out;
    unsigned char * dataNative = 	dataText;
    unsigned char *          tagNative        = tag;
    long unsigned   finalOutlen      = 0;
    int             rc               = ICC_OSSL_SUCCESS;
    static const char * functionName = "NativeInterface.GCM_FinalForUpdateEncrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DATA
    if ( debug ) {
        gslogMessagePrefix ("DATA_GCM tagNative : ");
        gslogMessageHex ((char*) tagNative, 0, (int) tagLen, 0, 0, NULL);
    }
#endif
    //if(gcmCtx == 0) gcmCtx = getOrfreeGCMContext(ockCtx, keyLen);
    //GCM Ctx cannot be null for subsequent updates
    rc = ((gcmCtx == 0) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS);
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM %s rc %d gcmCtx %x\n", functionName, rc, gcmCtx);
    }
#endif

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM rc %d gcmCtx=%x", (int) rc, gcmCtx);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
        if (dataLen > 0) {
            // update dataLen
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("DETAIL_GCM NI calling data Len > 0 calling ICC_AES_GCM_EncryptUpdate before ICC_AES_GCM_EncryptFinal  dataOffset %d dataLen %d outputOffset %d updateOutlen %ld\n",
                      dataOffset, dataLen, outOffset, updateOutlen);
            }
#endif
            rc = ICC_AES_GCM_EncryptUpdate(ockCtx, gcmCtx,
                 NULL, 0,
                 dataNative + dataOffset, dataLen,
                 outNative + outOffset, &updateOutlen);

#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("DETAIL_GCM NI rc ICC_AES_GCM_EncryptUpdate returned %d updateOutlen %ld\n", rc, updateOutlen);
            }
#endif
        }

        if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("DETAIL_GCM NI GCM_FinalForUpdateEncrypt_core updateOutlen %ld\n", updateOutlen);
            }
#endif
            rc = ICC_AES_GCM_EncryptFinal(ockCtx, gcmCtx,
                outNative + outOffset  + updateOutlen, &finalOutlen, tagNative);
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("DETAIL_GCM NI return rc %d from ICC_AES_GCM_EncryptFinal finalOutlen %ld updateOutlen %ld outOffset %d\n", rc, finalOutlen, updateOutlen, outOffset);
            }
#endif
            if (rc != ICC_OSSL_SUCCESS) {
                ockCheckStatus(ockCtx);
                return ICC_AES_GCM_CRYPTFINAL_FAILED;
            }
        } else {
            ockCheckStatus(ockCtx);
            return ICC_AES_GCM_CRYPTUPDATE_FAILED;
        }

    } else {
        ockCheckStatus(ockCtx);
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }
    return 0;
#else
    return -1;
#endif
}

char *getVersion(void) {
    ICC_STATUS status;
    ICC_CTX *ctx = NULL;
    void* buffer = NULL;

    ctx = ICC_Init(&status,NULL);
    buffer = calloc(10,1);
    ICC_GetValue(ctx,&status,ICC_VERSION,buffer,10);
    return buffer;
}

char getCharFromLong(unsigned long nb, int power) {
    char* ptr;
    nb = nb >> power;
    ptr = ((char *) &nb) + sizeof(long) - 1; // get last byte
    return *ptr;
}

void putLongtoByteArray(long number, char* bArray, int startIndex) {
    bArray[startIndex] = getCharFromLong(number,56);
    bArray[startIndex + 1] = getCharFromLong(number,48);
    bArray[startIndex + 2] = getCharFromLong(number,40);
    bArray[startIndex + 3] = getCharFromLong(number,32);
    bArray[startIndex + 4] = getCharFromLong(number,24);
    bArray[startIndex + 5] = getCharFromLong(number,16);
    bArray[startIndex + 6] = getCharFromLong(number,8);
    bArray[startIndex + 7] = getCharFromLong(number,0);
}

void printByteArray(char* name, unsigned char* input, int len) {
    int i = 0;
    printf ("%s: [", name);
    for (i = 0; i < len; i++) {
        if (i > 0) printf(":");
        printf("%02x",  input[i]);
    }
    printf("]\n");
}

void z_km_native(signed char* in, int inputLength, int inputOffset, signed char* out, int outputOffset, signed char* parm_block, long mode) {
    UDATA len = inputLength;
    UDATA _mode = mode;
    ECB(in+inputOffset, out+outputOffset, &len, parm_block, &_mode);
}

void z_kimd_native(signed char* in, int inputLength, int inputOffset, signed char* parm_block, long mode) {
    UDATA _mode = mode;
    UDATA len = inputLength;
    GHASH(in+inputOffset, &len, parm_block, &_mode);
}

void handleIV(int ivLength, int keyLen, int blockSize, int J0Offset, char* iv, char* key, char* addedParams) {
#if defined(S390_PLATFORM) || defined(__MVS__)
    // Computing hash-key
    int offset = 0;
    int fc = 0;
    int i = 0;
    int lenn = 0;
    int lastIVLen = blockSize;
    int ivLengthOG = ivLength;
    char* ghashParamBlockPtr = NULL;

    if (ivLength == 12) {
        addedParams[J0Offset + blockSize - 1] = 1;
        memcpy(addedParams + J0Offset, iv, ivLength);
    } else {
        char hashSubkey[blockSize];
        char zeros[blockSize];
        char hashSubkeyParamBlock[keyLen];
        char ghashParamBlock[2 * blockSize];

        fc = (keyLen == 16) ? 18 : (keyLen == 24) ? 19 : 20;

        memset(&hashSubkey,0, blockSize);
        memset(&zeros,0, blockSize);
        memcpy(&hashSubkeyParamBlock, key, keyLen);
        z_km_native((signed char*) &zeros,blockSize,0,(signed char*) &hashSubkey,0,(signed char*) &hashSubkeyParamBlock,fc);

        // Computing GHash for IV
        ghashParamBlockPtr = (char*) &ghashParamBlock;
        memset(&ghashParamBlock,0, blockSize);
        memcpy(ghashParamBlockPtr + blockSize, &hashSubkey, blockSize);

        if (ivLength >= blockSize) {
            lenn = ivLength - (ivLength % blockSize);
            z_kimd_native((signed char *) iv, lenn, offset, (signed char *) &ghashParamBlock, 65);
            ivLength -= lenn;
            offset += lenn;
        }

        if (ivLength > 0) lastIVLen *= 2;
        char lastIV[lastIVLen];
        memset(&lastIV,0,lastIVLen);
        if (ivLength > 0) memcpy(&lastIV, iv + offset, ivLength);

        // Appending IV.length
        putLongtoByteArray(ivLengthOG * 8, (signed char *) &lastIV, lastIVLen - 8);
        z_kimd_native((signed char *) &lastIV, lastIVLen, 0, (signed char *) &ghashParamBlock, 65);

        // Updating addedParam
        for (i = 0; i < blockSize; i++) {
            addedParams[J0Offset + i] = ghashParamBlock[i];
        }
    }
#endif
}

int checkTagMismatch(char* input, int inputLen, char* parm_block, int tagOffset, int tagLen) {
#if defined (S390_PLATFORM) || defined(__MVS__)
    // check entire authentication tag for time-consistency

    int i = 0;
    int mismatch = 0;

#if 0
    char tag[tagLen];
    char newTag[tagLen];

    memcpy(&tag, input + inputLen, tagLen);
    memcpy(&newTag, parm_block + tagOffset, tagLen);
#else
    char *tag = input + inputLen;
    char *newTag = parm_block + tagOffset;
#endif
    for (i = 0; i < tagLen; i++) mismatch |= tag[i] ^ newTag[i];

    return (mismatch == 0) ? 0 : -1;
#else
    return 0;
#endif
}

/*============================================================================
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_decrypt_core
* Signature:
*/
int GCM_decrypt_core(JNIEnv *env, ICC_CTX* ockCtx, ICC_AES_GCM_CTX* gcmCtx,
    unsigned char * key, int keyLen,
    unsigned char * iv,  int ivLen,
    unsigned char * ciphertext, int ciphertextOffset, int ciphertextLen,
    unsigned char * plaintext, int plaintextOffset,
    unsigned char * aad, int aadLen, int tagLen) {
    long unsigned updateOutlen   = 0;
    long unsigned updateAADlen   = 0;
    long unsigned finalOutlen    = 0;
    int           rc             = ICC_OSSL_SUCCESS;
    static const char * functionName = "NativeInterface.GCM_decrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

    if (gcmCtx == 0) gcmCtx = getOrfreeGCMContext(ockCtx, keyLen);

    rc = gcmCtx != NULL ? ICC_OSSL_SUCCESS : ICC_OSSL_FAILURE;
    if (rc == ICC_OSSL_SUCCESS) {
        rc = ICC_AES_GCM_Init (ockCtx, gcmCtx, iv, ivLen, key, keyLen);

        if (rc == ICC_OSSL_SUCCESS) {

            if (aadLen > 0) {
                rc = ICC_AES_GCM_DecryptUpdate(ockCtx, gcmCtx,aad, aadLen,NULL, 0,NULL, &updateAADlen);
            }

            if (rc == ICC_OSSL_SUCCESS) {
                if (ciphertextLen > 0) {
                    rc = ICC_AES_GCM_DecryptUpdate(ockCtx, gcmCtx,NULL, 0,ciphertext + ciphertextOffset, ciphertextLen, plaintext + plaintextOffset, &updateOutlen);
                }

                // that needs to catch a hash mismatch condition
                if ( rc == ICC_OSSL_SUCCESS ) {
                    // obtain up to last block of plaintext and provide tag to compare
                    rc = ICC_AES_GCM_DecryptFinal(ockCtx, gcmCtx,plaintext + plaintextOffset + updateOutlen, &finalOutlen,
                        ciphertext + ciphertextOffset + ciphertextLen, tagLen);

                    if (rc != ICC_OSSL_SUCCESS ) {
                        // entered an error condition here
                        if (rc == -1 ) {
                            // hash mismatch error
                            ockCheckStatus(ockCtx);
                            return ICC_AES_GCM_TAG_MISMATCH;
                        } else {
                            // generic error condition
                            ockCheckStatus(ockCtx);
                            return ICC_AES_GCM_CRYPTFINAL_FAILED;
                        }
                    }
                } else {
                    ockCheckStatus(ockCtx);
                    return ICC_AES_GCM_CRYPTUPDATE_FAILED;
                }
            } else {
                ockCheckStatus(ockCtx);
                return ICC_AES_GCM_CRYPTUPDATE_FAILED;
            }
        } else {
            ockCheckStatus(ockCtx);
            return ICC_AES_GCM_INIT_FAILED;
        }
    } else {
        /* GCM CTX Failed - no need to free it. */
        ockCheckStatus(ockCtx);
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }
    return 0;
}

/*
 *  Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  Method:    do_GCM_decryptFastJNI_WithHardwareSupport
 *  */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1decryptFastJNI_1WithHardwareSupport
(JNIEnv *env, jclass unusedClass, jint keyLen, jint ivLen, jint ciphertextOffset, jint ciphertextLen, jint plaintextOffset,
    jint aadLen, jint tagLen, jlong parameterBuffer, jbyteArray inputJ, jint inputOffset, jbyteArray outputJ, jint outputOffset) {
    // Setting static values
    int            J0Offset = 64;
    int            blockSize = 16;
    int            counterValueOffset = 12;
    int            tagOffset = 16;
    int            keyOffset = 80;
    int            ret = -1;
    long           mode = 0;
    long           len = 0;
    long           alen = 0;
    jboolean       isCopy = 0;
    unsigned char* input = NULL;
    unsigned char* output = NULL;
    unsigned char* parameters = NULL;
    unsigned char* iv = NULL;
    unsigned char* aad = NULL;
    unsigned char* parm_block = NULL;

    // Getting params
    if (inputJ != NULL) {
        input = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, inputJ,  &isCopy));
    }
    if (outputJ != NULL) {
        output = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, outputJ,  &isCopy));
    }
    parameters = (unsigned char*)parameterBuffer;
    iv = parameters;
    aad = parameters + ivLen;
    mode = *((long long*) (parameters + ivLen + aadLen + tagLen)); // Assuming sizeof(long) == 8. In 31 bit mode a long is 4 bytes, long long is 8 bytes in both 31 and 64.
    parm_block = (unsigned char *) parameters + ivLen + aadLen + tagLen + 8;
    len = ciphertextLen;
    alen = aadLen;

    // Handle IV (different implementation based on the IV size)
    handleIV(ivLen, keyLen, blockSize, J0Offset, (char*) iv, (char*) (parm_block + keyOffset), (char*) parm_block);
    memcpy(parm_block + counterValueOffset, parm_block + J0Offset + blockSize - 4, 4); // Add Counter Value

    zS390((input != NULL) ? (input + inputOffset) : NULL, (output != NULL) ? (output + outputOffset) : NULL, aad, &len, &alen, parm_block, &mode);

    ret = checkTagMismatch((input != NULL) ? (char*) (input + inputOffset) : NULL, len, (char*) parm_block, tagOffset, tagLen);

    if (input != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, inputJ, input, 0);
    }
    if (output != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, outputJ, output, 0);
    }

    return ret;
}

/*
 *  * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  * Method:    do_GCM_decryptFastJNI
 *  */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1decryptFastJNI
(JNIEnv *env, jclass unusedClass, jlong ockContextId, jlong gcmCtxId, jint keyLen, jint ivLen, jint ciphertextOffset, jint ciphertextLen, jint plaintextOffset, jint aadLen, jint tagLen, jlong parameterBuffer, jlong inputBuffer, jlong outputBuffer) {
    ICC_CTX*        ockCtx           = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char*  parameters       = (unsigned char*)parameterBuffer;
    unsigned char*  ciphertext		 = (unsigned char*)inputBuffer;
    unsigned char*  plaintext		 = (unsigned char*)outputBuffer;
    unsigned char*  iv               = parameters;
    unsigned char*  aad              = parameters + ivLen;
    unsigned char*  key              = parameters + ivLen + aadLen;
    ICC_AES_GCM_CTX* gcmCtx          = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);
    int             ret              = -1;

    ret = GCM_decrypt_core(env, ockCtx, gcmCtx,
            key             , keyLen,
            iv              , ivLen,
            ciphertext		, ciphertextOffset, ciphertextLen,
            plaintext		, plaintextOffset,
            aad             , aadLen, tagLen);

    return (jint)ret;
}

/*
 *  Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  Method:    do_GCM_decrypt
 *  */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1decrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen, jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen, jbyteArray plaintext, jint plaintextOffset, jbyteArray aad, jint aadLen, jint tagLen) {
    static const char * functionName = "NativeInterface.do_GCM_decrypt";
    ICC_CTX *    ockCtx          = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char * keyNative    = NULL;
    unsigned char * ivNative     = NULL;
    unsigned char *      plaintextNative  = NULL;
    unsigned char *      ciphertextNative = NULL;
    unsigned char *      aadNative        = NULL;
    int         rc               = ICC_OSSL_SUCCESS;
    int         ret              = -1;
    jboolean    isCopy           = 0;
    ICC_AES_GCM_CTX* gcmCtx      = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

    ivNative         = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv        , &isCopy));
    keyNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key       , &isCopy));
    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
    plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext , &isCopy));
    aadNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad       , &isCopy));

    rc = (ivNative == NULL || keyNative == NULL || ciphertextNative == NULL || plaintextNative == NULL || aadNative == NULL) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
            gslogMessage ("DETAIL_GCM rc after PrimitiveArrayCritical %d", (int) rc);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
        ret = GCM_decrypt_core (env, ockCtx, gcmCtx,
                keyNative, keyLen,
                ivNative, ivLen,
                ciphertextNative, ciphertextOffset, ciphertextLen,
                plaintextNative, plaintextOffset,
                aadNative, aadLen, tagLen);
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv,  ivNative, 0);
    }

    if (ciphertextNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if (plaintextNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

    if (aadNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

//      if ( gcmCtx != NULL) {
//              PutGCMContext(thrGcmCtx, ockCtx);
//      }
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM ret=%d", (int) ret);
    }
#endif
    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return(jint)ret;
}

/*============================================================================
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    GCM_encrypt_core
* Signature:
*/
int GCM_encrypt_core(JNIEnv* env, ICC_CTX* ockCtx, ICC_AES_GCM_CTX* gcmCtx,
    unsigned char* key   , int keyLen,
    unsigned char* iv    , int ivLen,
    unsigned char* aad   , int aadLen,
    unsigned char* tag   , int tagLen,
    unsigned char* plain , int plaintextLen, int plaintextOffset,
    unsigned char* cipher, int ciphertextOffset) {
    unsigned char * keyNative        = key;
    unsigned char * ivNative         = iv;
    unsigned char *          plaintextNative  = plain;
    unsigned char * ciphertextNative = cipher;
    unsigned char *          aadNative        = aad;
    unsigned char *          tagNative        = tag;
    unsigned long int        updateOutlen     = 0;
    unsigned long   updateAADlen     = 0;
    long unsigned   finalOutlen      = 0;
    int             rc               = ICC_OSSL_SUCCESS;
    static const char * functionName = "NativeInterface.GCM_encrypt_core";

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DATA
    if ( debug ) {
        gslogMessagePrefix ("DATA_GCM ivNative : ");
        gslogMessageHex ((char*) ivNative, 0, (int) ivLen, 0, 0, NULL);

        gslogMessagePrefix ("DATA_GCM keyNative : ");
        gslogMessageHex ((char*) keyNative, 0, (int) keyLen, 0, 0, NULL);

        gslogMessagePrefix ("DATA_GCM iphertextNative : ");
        gslogMessageHex ((char*) plaintextNative, 0, (int) plaintextLen, 0, 0, NULL);

        gslogMessagePrefix ("DATA_GCM aadNative : ");
        gslogMessageHex ((char*) aadNative, 0, (int) aadLen, 0, 0, NULL);
    }
#endif
    if (gcmCtx == 0) {
        gcmCtx = getOrfreeGCMContext(ockCtx, keyLen);
    }

    rc = gcmCtx != NULL ? ICC_OSSL_SUCCESS : ICC_OSSL_FAILURE;
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
            gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_CTX_new %d gcmCtx=%x", (int) rc, gcmCtx);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
            rc = ICC_AES_GCM_Init(ockCtx, gcmCtx, ivNative, ivLen, keyNative, keyLen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
                gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_iNIt %d", (int) rc);
        }
#endif
        if (rc == ICC_OSSL_SUCCESS) {

            if ((aadLen > 0) && (plaintextLen > 0)) {
                    rc = ICC_AES_GCM_EncryptUpdate(ockCtx, gcmCtx,
                                    aadNative, aadLen,
                                    plaintextNative + plaintextOffset, plaintextLen,
                                    ciphertextNative + ciphertextOffset, &updateOutlen);
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                        gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_EncryptUpdate(aadLen > 0 & plaintextLen > 0) %d updateOutlen %d", (int) rc, updateOutlen);
                }
#endif
            } else {
                if (aadLen > 0) {
                    // update AAD
                    rc = ICC_AES_GCM_EncryptUpdate(ockCtx, gcmCtx,
                                    aadNative, aadLen,
                                    NULL, 0,
                                    NULL, &updateAADlen);
#ifdef DEBUG_GCM_DETAIL
                    if ( debug ) {
                            gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_EncryptUpdate(aadLen > 0) %d updateAADlen %d", (int) rc, updateAADlen);
                    }
#endif
                }
                if (plaintextLen > 0) {
                    // update plaintext
                    rc = ICC_AES_GCM_EncryptUpdate(ockCtx, gcmCtx,
                                NULL, 0,
                                plaintextNative + plaintextOffset, plaintextLen,
                                ciphertextNative + ciphertextOffset, &updateOutlen);
#ifdef DEBUG_GCM_DETAIL
                if ( debug ) {
                        gslogMessage ("DETAIL_GCM rc ICC_AES_GCM_EncryptUpdate(plaintextLen > 0) %d updateOutlen %d", (int) rc, updateOutlen);
                }
#endif
                }
            }
            if (rc == ICC_OSSL_SUCCESS) {
                rc = ICC_AES_GCM_EncryptFinal(ockCtx, gcmCtx,
                        ciphertextNative + ciphertextOffset + updateOutlen, &finalOutlen, tagNative);

                if (rc == ICC_OSSL_SUCCESS) {

                } else {
                    ockCheckStatus(ockCtx);
                    return ICC_AES_GCM_CRYPTFINAL_FAILED;
                }
            } else {
                ockCheckStatus(ockCtx);
                return ICC_AES_GCM_CRYPTUPDATE_FAILED;
            }
        } else {
            ockCheckStatus(ockCtx);
            return ICC_AES_GCM_INIT_FAILED;
        }
    } else {
        ockCheckStatus(ockCtx);
        return ICC_AES_GCM_CTX_NEW_FAILED;
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }
    return 0;
}

/*
 *  * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  * Method:    do_GCM_checkHardwareGCMSupport
 *  */
FUNC *JCC_OS_helpers(ICC_CTX *ctx);
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1checkHardwareGCMSupport(JNIEnv *env, jclass unusedClass, jlong ockContextId) {
    ICC_CTX * ctx = (ICC_CTX *)((intptr_t) ockContextId);
    FUNC*     funcPtr = ICC_OS_helpers(ctx);

    if ((NULL == funcPtr) || (NULL == funcPtr[1].func) || (NULL == funcPtr[1].name)) {
        return -1;
    } else {
        ECB = (ECB_FuncPtr)funcPtr[3].func;     // z_km_native
        GHASH = (GHASH_FuncPtr)funcPtr[4].func; // z_kimd_native
        zS390 = (zS390_FuncPtr)funcPtr[1].func; // s390_kmgcm_native
        return 1;
    }
}

/*
 *  * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  * Method:    do_GCM_encryptFastJNI_WithHardwareSupport
 *  */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1encryptFastJNI_1WithHardwareSupport
(JNIEnv *env, jclass unusedClass, jint keyLen, jint ivLen, jint plaintextOffset, jint plaintextLen, jint ciphertextOffset,
    jint aadLen, jint tagLen, jlong parameterBuffer, jbyteArray inputJ, jint inputOffset, jbyteArray outputJ, jint outputOffset) {
    long           mode = 0;
    long           len = 0;
    long           alen = 0;
    jboolean       isCopy = 0;
    int            J0Offset = 64;
    int            blockSize = 16;
    int            counterValueOffset = 12;
    int            keyOffset = 80;
    unsigned char* input = NULL;
    unsigned char* output = NULL;
    unsigned char* parameters = NULL;
    unsigned char* iv = NULL;
    unsigned char* aad = NULL;
    unsigned char* parm_block = NULL;
    unsigned char* tag = NULL;

    // Getting params
    if (inputJ != NULL) {
        input = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, inputJ, &isCopy));
    }
    if (outputJ != NULL) {
        output = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, outputJ, &isCopy));
    }
    parameters       = (unsigned char*)parameterBuffer;
    iv               = parameters;
    aad              = parameters + ivLen;
    mode = *((long long*) (parameters + ivLen + aadLen + tagLen)); // Assuming sizeof(long) == 8. In 31 bit mode a long is 4 bytes, long long is 8 bytes in both 31 and 64.
    parm_block = parameters + ivLen + aadLen + tagLen + 8;
    len = plaintextLen;
    alen = aadLen;

    // Handle IV (different implementation based on the IV size)
    handleIV(ivLen, keyLen, blockSize, J0Offset, (char*) iv, (char*) (parm_block + keyOffset), (char*) parm_block);
    memcpy(parm_block + counterValueOffset, parm_block + J0Offset + blockSize - 4, 4); // Add Counter Value

    zS390((input != NULL) ? (input + inputOffset) : NULL, (output != NULL) ? (output + outputOffset) : NULL, aad, &len, &alen, parm_block, &mode);

    // Copy tag
    tag = parameters + ivLen + aadLen + keyLen;
    memcpy(tag, parm_block + 16, tagLen); // Add tag to output

    if (input != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, inputJ, input, 0);
    }
    if (output != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, outputJ, output, 0);
    }

    return 0;
}

/*
 *  * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  * Method:    do_GCM_encryptFastJNI
 *  */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1encryptFastJNI
(JNIEnv *env, jclass unusedClass, jlong ockContextId, jlong gcmCtxId, jint keyLen, jint ivLen, jint plaintextOffset, jint plaintextLen, jint ciphertextOffset, jint aadLen, jint tagLen, jlong parameterBuffer, jlong inputBuffer, jlong outputBuffer) {
    ICC_CTX*        ockCtx           = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char*  parameters       = (unsigned char*)parameterBuffer;
    unsigned char*  plaintextNative  = (unsigned char*)inputBuffer;
    unsigned char*  ciphertextNative = (unsigned char*)outputBuffer;
    unsigned char*  iv               = parameters;
    unsigned char*  aad              = parameters + ivLen;
    unsigned char*  key              = parameters + ivLen + aadLen;
    unsigned char*  tag              = parameters + ivLen + aadLen + keyLen;
    ICC_AES_GCM_CTX* gcmCtx          = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);
    int             ret              = -1;

    ret = GCM_encrypt_core(env, ockCtx, gcmCtx,
            key             , keyLen,
            iv              , ivLen,
            aad             , aadLen,
            tag             , tagLen,
            plaintextNative , plaintextLen, plaintextOffset,
            ciphertextNative, ciphertextOffset);

    return (jint)ret;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_encrypt
 * Signature: (J[BI[BI[BII[BI[BI[B)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1encrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen, jbyteArray plaintext, jint plaintextOffset, jint plaintextLen, jbyteArray ciphertext, jint ciphertextOffset, jbyteArray aad, jint aadLen, jbyteArray tag, jint tagLen) {
    static const char * functionName = "NativeInterface.do_GCM_encrypt";
    ICC_CTX *    ockCtx              = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char * keyNative        = NULL;
    unsigned char * ivNative         = NULL;
    unsigned char *          plaintextNative  = NULL;
    unsigned char * ciphertextNative = NULL;
    unsigned char *          aadNative        = NULL;
    unsigned char *          tagNative        = NULL;
    int             rc               = ICC_OSSL_SUCCESS;
    int             ret              = -1;
    jboolean        isCopy           = 0;
    ICC_AES_GCM_CTX* gcmCtx          = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

    ivNative         = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,  &isCopy));
    keyNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    if (plaintextLen > 0) {
        plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));
    }
    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
    aadNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, &isCopy));
    tagNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, tag, &isCopy));

    rc = (ivNative == NULL || keyNative == NULL || ciphertextNative == NULL || tagNative == NULL || aadNative == NULL) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;

    if (rc == ICC_OSSL_SUCCESS) {
        ret = GCM_encrypt_core(env, ockCtx, gcmCtx,
                keyNative             , keyLen,
                ivNative              , ivLen,
                aadNative             , aadLen,
                tagNative             , tagLen,
                plaintextNative , plaintextLen, plaintextOffset,
                ciphertextNative, ciphertextOffset);
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv,  ivNative, 0);
    }

    if (tagNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, tag, tagNative, 0);
    }

    if (aadNative != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

    if (plaintextNative != NULL && plaintextLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

    if (ciphertextNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if ( debug ) {
            gslogFunctionExit(functionName);
    }

    return (jint)ret;
}
//============================================================================
///*
// * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
//  * Method:    do_GCM_delete
//   * Signature: (JJ)V
//    */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_GCM_1delete
    (JNIEnv *env, jclass thisObj, jlong ockContextId) {
    static const char * functionName = "NativeInterface.do_GCM_delete";
    ICC_CTX * ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
    if	( debug ) {
        gslogFunctionEntry(functionName);
    }

    getOrfreeGCMContext(ockCtx, 0);

    if ( debug ) {
        gslogFunctionExit(functionName);
    }
}

/* Return to Java Space a flag informing if TLS (Thread Local Storage) is used by the native GCM code
 * or not.
 *
 * Currently this is controlled per platform since there is a compiler bug in AIX that prevents TLS use.
 * TLS use in native code should be preferred as it is higher performing.
 *
 * Return Value 0 = TLS Enabled
 * Return Value 1 = TLS Disabled
 */
//JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_get_1GCM_1TLSEnabled
//	(JNIEnv *env, jclass thisObj) {
//	static const char * functionName = "NativeInterface.get_GCM_TLSEnabled";
//    int ret = 1;
//
//	if (debug) {
//	    gslogFunctionEntry(functionName);
//	}
//
//	if (debug) gslogFunctionExit(functionName);
//
//	return ret;
//}

JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_create_1GCM_1context
    (JNIEnv *env, jclass thisObj, jlong ockContextId) {
    static const char * functionName = "NativeInterface.create_GCM_context";
    ICC_CTX * ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
    ICC_AES_GCM_CTX* gcmCtx = NULL;
    int              rc = 0;

    if (debug) gslogFunctionEntry(functionName);
    if (debug) gslogFunctionExit(functionName);
    gcmCtx = ICC_AES_GCM_CTX_new(ockCtx);
    rc = ICC_AES_GCM_CTX_ctrl(ockCtx, gcmCtx, ICC_AES_GCM_CTRL_TLS13, 0, NULL);
    if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("ICC_AES_GCM_CTX_ctrl failed rc = %d\n", rc);
        }
#endif
        if (gcmCtx != NULL) {
            ICC_AES_GCM_CTX_free (ockCtx, gcmCtx);
        }
        gcmCtx = NULL;
    }
    return (jlong)gcmCtx;
}

//============================================================================
/*
* Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
* Method:    free_GCM_ctx
* Signature: (JJ)V
*/
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_free_1GCM_1ctx
    (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmContextId) {
    static const char * functionName = "NativeInterface.free_1GCM_1ctx";
    ICC_CTX *         ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
    ICC_AES_GCM_CTX * gcmCtx = (ICC_AES_GCM_CTX *)((intptr_t) gcmContextId);
    if	( debug ) {
        gslogFunctionEntry(functionName);
    }
    if (gcmCtx != NULL) {
      ICC_AES_GCM_CTX_free(ockCtx,gcmCtx);
      gcmCtx = NULL;
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_UpdForUpdateEncrypt
 * Signature:
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1UpdForUpdateEncrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId,
 jbyteArray plaintext, jint plaintextOffset, jint plaintextLen, jbyteArray ciphertext, jint ciphertextOffset) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    static const char * functionName = "NativeInterface.do_GCM_UpdForUpdateEncrypt";
    ICC_CTX *    ockCtx              = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char *          plaintextNative  = NULL;
    unsigned char * ciphertextNative = NULL;
    int             rc               = ICC_OSSL_SUCCESS;
    int             ret              = -1;
    jboolean        isCopy           = 0;
    /*jmethodID longGetValueId;
    jmethodID longSetValueId;*/
    unsigned long updateOutlen = 0;
    ICC_AES_GCM_CTX* gcmCtx          = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("NI do_GCM_UpdForUpdateEncrypt thisObj %x\n", thisObj);
    }
#endif

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("NI do_GCM_UpdForUpdateEncrypt updateOutlen %ld\n", updateOutlen);
    }
#endif
    if (plaintextLen > 0) {
        plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));
    }
    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));

    rc = (ciphertextNative == NULL || ((plaintextLen > 0) && (plaintextNative == NULL))) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;

    if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI Calling GCM_update_encrypt_core\n");
        }
#endif
        ret = GCM_UpdForUpdateEncrypt_core(env, ockCtx, gcmCtx,
                plaintextNative , plaintextLen, plaintextOffset,
                ciphertextNative, ciphertextOffset, &updateOutlen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI ret from GCM_update_encrypt_core  %d modified updateOutlen %ld ICC_OSSL_SUCCESS=%d\n", ret, updateOutlen, ICC_OSSL_SUCCESS);
        }
#endif
        if (ret == 0) {
#ifdef DEBUG_GCM_DETAIL
            if ( debug ) {
                gslogMessage ("NI set the value of jupdateOutlen\n");
             }
#endif
        }
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (plaintextNative != NULL && plaintextLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

    if (ciphertextNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return (jint)ret;
#else
    return -1;
#endif
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_FinalForUpdateEncrypt
 * Signature:
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1FinalForUpdateEncrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId, jbyteArray key, jint keyLen,
 jbyteArray iv, jint ivLen, jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
  jbyteArray ciphertext, jint ciphertextOffset, jbyteArray aad, jint aadLen, jbyteArray tag, jint tagLen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    static const char * functionName = "NativeInterface.do_GCM_FinalUpdateEncrypt";
    ICC_CTX *    ockCtx              = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char * keyNative        = NULL;
    unsigned char * ivNative         = NULL;
    unsigned char *          plaintextNative  = NULL;
    unsigned char * ciphertextNative = NULL;
    unsigned char *          aadNative        = NULL;
    unsigned char *          tagNative        = NULL;
    int             rc               = ICC_OSSL_SUCCESS;
    int             ret              = -1;
    jboolean        isCopy           = 0;
    unsigned long   updateOutlen	 = 0;

    ICC_AES_GCM_CTX* gcmCtx          = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);

    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("NI do_GCM_FinalForUpdateEncrypt updateOutlen %ld\n", updateOutlen);
    }
#endif
    ivNative         = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,  &isCopy));
    keyNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    if (plaintextLen > 0) {
        plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext,  &isCopy));
    }

    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
    if (aadLen > 0) {
        aadNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, &isCopy));
    }
    tagNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, tag, &isCopy));

    rc = (ivNative == NULL || keyNative == NULL || ciphertextNative == NULL || tagNative == NULL ||
    ((aadLen > 0 ) && (aadNative == NULL)) || ((plaintextLen > 0 ) && (plaintextNative == NULL))) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;

    if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI Calling GCM_FinalForUpdateEncrypt_core\n");
        }
#endif
        ret = GCM_FinalForUpdateEncrypt_core(env, ockCtx, gcmCtx, tagNative, tagLen, plaintextNative, plaintextOffset, plaintextLen, ciphertextNative, ciphertextOffset, updateOutlen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI ret from GCM_FinalForUpdateEncrypt_core %d\n", ret);
        }
#endif
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv,  ivNative, 0);
    }

    if (tagNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, tag, tagNative, 0);
    }

    if (aadNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

    if (plaintextNative != NULL && plaintextLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

    if (ciphertextNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return (jint)ret;
#else
    return -1;
#endif
}
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_UpdForUpdateDecrypt
 * Signature:
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1UpdForUpdateDecrypt
    (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen, jbyteArray plaintext, jint plaintextOffset) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    static const char * functionName = "NativeInterface.do_GCM_UpdForUpdateDecrypt";
    ICC_CTX *    ockCtx          = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char *      plaintextNative  = NULL;
    unsigned char *      ciphertextNative = NULL;
    int         rc               = ICC_OSSL_SUCCESS;
    int         ret              = -1;
    jboolean    isCopy           = 0;
    unsigned long  updateOutlen  = 0;
    ICC_AES_GCM_CTX* gcmCtx      = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }
    if (ciphertextLen > 0) {
        ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
    }
    plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext , &isCopy));

    rc = (((ciphertextLen > 0) && (ciphertextNative == NULL)) || plaintextNative == NULL) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM rc after PrimitiveArrayCritical %d", (int) rc);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
        gslogMessage ("DETAIL_GCM NI calling GCM_UpdForUpdateDecrypt_core ciphertextOffSet %d ciphertextLen %d plaintextOffSet %d \n",
            ciphertextOffset, ciphertextLen, plaintextOffset);
        }
#endif
        ret = GCM_UpdForUpdateDecrypt_core (env, ockCtx, gcmCtx,
        ciphertextNative, ciphertextOffset, ciphertextLen,
        plaintextNative, plaintextOffset,
        &updateOutlen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM NI GCM_update_decrypt_core returns %d updateOutlen %ld\n", ret, updateOutlen);
        }
#endif
    } else {
    ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (ciphertextNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if (plaintextNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM ret=%d", (int) ret);
    }
#endif
    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return(jint)ret;
#else
    return -1;
#endif
}
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_InitForUpdateDecrypt
 * Signature:
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1InitForUpdateDecrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
jbyteArray aad, jint aadLen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    static const char * functionName = "NativeInterface.do_GCM_InitForUpdateDecrypt";
    ICC_CTX *    ockCtx          = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char * keyNative    = NULL;
    unsigned char * ivNative     = NULL;
    unsigned char *      aadNative        = NULL;
    int         rc               = ICC_OSSL_SUCCESS;
    int         ret              = -1;
    jboolean    isCopy           = 0;
    unsigned long  updateOutlen  = 0;
    ICC_AES_GCM_CTX* gcmCtx      = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI do_GCM_InitForUpdateDecrypt ockContextId %ld gcmCtxId %ld keyLen %d ivLen %d aadLen %d\n", ockContextId, gcmCtxId, keyLen, ivLen, aadLen);
    }
#endif
    ivNative         = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv        , &isCopy));
    keyNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key       , &isCopy));

    if (aadLen > 0) {
        aadNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad       , &isCopy));
    }

    rc = (ivNative == NULL || keyNative == NULL || ((aadLen > 0) && (aadNative == NULL))) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM rc after PrimitiveArrayCritical %d", (int) rc);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM NI calling GCM_InitForUdateDecryptCore keyLen %d ivLen %d addLen %d \n",
                keyLen, ivLen,  aadLen);
        }
#endif
        ret = GCM_InitForUpdateDecrypt_core (env, ockCtx, gcmCtx,
                keyNative, keyLen,
                ivNative, ivLen,
                aadNative, aadLen,  &updateOutlen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM NI GCM_InitForUpdateDecrypt_core returns %d updateOutlen %ld\n", ret, updateOutlen);
        }
#endif
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv,  ivNative, 0);
    }

    if (aadNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM ret=%d", (int) ret);
    }
#endif
    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return(jint)ret;
#else
    return -1;
#endif
}
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_FinalForUpdateDecrypt
 * Signature:
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1FinalForUpdateDecrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId,
jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
jbyteArray plaintext, jint plaintextOffset, jint plaintextLen, jbyteArray aad, jint aadLen,
jint tagLen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    static const char * functionName = "NativeInterface.do_GCM_FinalForUpdateDecrypt";
    ICC_CTX *    ockCtx          = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char *      plaintextNative  = NULL;
    unsigned char *      ciphertextNative = NULL;
    unsigned char *      aadNative        = NULL;
    int         rc               = ICC_OSSL_SUCCESS;
    int         ret              = -1;
    jboolean    isCopy           = 0;
    long updateOutlen            = 0;

    ICC_AES_GCM_CTX* gcmCtx      = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("NI DETAIL_GCM   do_GCM_FinalForUpdateDecrypt updateOutlen %ld ciphertexLen %d, plaintextLen %d aadLen %d\n", updateOutlen, ciphertextLen, plaintextLen, aadLen);
    }
#endif
    if (ciphertextLen > 0) {
        ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, ciphertext, &isCopy));
    }
    if (plaintextLen > 0) {
        plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, plaintext , &isCopy));
    }
    if (aadLen > 0) {
        aadNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad       , &isCopy));
    }

    rc = (((ciphertextLen > 0) && (ciphertextNative == NULL)) || ((plaintextLen > 0) && (plaintextNative == NULL))
    || ((aadLen > 0) && (aadNative == NULL))) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM rc after PrimitiveArrayCritical %d", (int) rc);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("NI doGCM_FinalForUpdateDecrypt updateOutLen = %ld\n", updateOutlen);
        }
#endif
        ret = GCM_FinalForUpdateDecrypt_core (env, ockCtx, gcmCtx,
                ciphertextNative, ciphertextOffset, ciphertextLen,
                plaintextNative, plaintextOffset,
                tagLen, updateOutlen);
#ifdef DEBUG_GCM_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_GCM GCM_FinalForUdateDerypt_core ret = %d updateOutLen = %ld\n", rc, updateOutlen);
        }
#endif
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (ciphertextNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if (plaintextNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

    if (aadNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM ret=%d", (int) ret);
    }
#endif
    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return(jint)ret;
#else
    return -1;
#endif
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_GCM_InitForUpdateEncrypt
 * Signature:
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1GCM_1InitForUpdateEncrypt
(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong gcmCtxId, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
jbyteArray aad, jint aadLen) {
#if defined(AIX) || defined(WINDOWS) || defined(MAC) || defined (LINUX) || defined(__MVS__)
    static const char * functionName = "NativeInterface.do_GCM_InitForUpdateEncrypt";
    ICC_CTX *    ockCtx          = (ICC_CTX *)((intptr_t) ockContextId);
    unsigned char * keyNative    = NULL;
    unsigned char * ivNative     = NULL;
    unsigned char *      aadNative        = NULL;
    int         rc               = ICC_OSSL_SUCCESS;
    int         ret              = -1;
    jboolean    isCopy           = 0;
    unsigned long updateOutlen   = 0;
    ICC_AES_GCM_CTX* gcmCtx      = (ICC_AES_GCM_CTX*)((intptr_t) gcmCtxId);

    if ( debug ) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI do_GCM_InitForUpdateDecrypt ockContextId %ld gcmCtxId %ld keyLen %d ivLen %d aadLen %d\n", ockContextId, gcmCtxId, keyLen, ivLen, aadLen);
    }
#endif
    ivNative         = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv        , &isCopy));
    keyNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key       , &isCopy));

    if (aadLen  > 0) {
        aadNative        = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad       , &isCopy));
    }

    rc = (ivNative == NULL || keyNative == NULL || ((aadLen >0) &&  (aadNative == NULL))) ? ICC_OSSL_FAILURE : ICC_OSSL_SUCCESS;
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM rc after PrimitiveArrayCritical %d", (int) rc);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI calling GCM_InitForUdateEncrypt_core keyLen %d ivLen %d  addLen %d \n",
            keyLen, ivLen, aadLen);
    }
#endif
    ret = GCM_InitForUpdateEncrypt_core (env, ockCtx, gcmCtx,
            keyNative, keyLen,
            ivNative, ivLen,
            aadNative, aadLen, &updateOutlen);
#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM NI GCM_InitForUpdateEncrypt_core returns %d updateOutlen %ld\n", ret, updateOutlen);
    }
#endif
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv,  ivNative, 0);
    }

    if (aadNative != NULL ) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

#ifdef DEBUG_GCM_DETAIL
    if ( debug ) {
        gslogMessage ("DETAIL_GCM ret=%d", (int) ret);
    }
#endif
    if ( debug ) {
        gslogFunctionExit(functionName);
    }

    return(jint)ret;
#else
    return -1;
#endif
}
