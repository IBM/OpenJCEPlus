/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

#define NID_X25519              1034
#define NID_X448                1035
#define NID_ffdh                28
#define NID_ffdhe2048           1126
#define NID_ffdhe3072           1127
#define NID_ffdhe4096           1128
#define NID_ffdhe6144           1129
#define NID_ffdhe8192           1130
#define NID_ED25519             1087
#define NID_ED448               1088

/* Note: when making ICC_D2i calls do not pass the address of a pointer allocated
 by GetPrimitiveArrayCritical.  Instead make a copy and pass the address of the copied pointer
   For Example,  instead of  passing  parameterBytesNative, 
   first create a copy:  pParameterBytes = parameterBytesNative and pass &pParameterBytes. 
   d2i calls increment the  pointer.*/
 
//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_generate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1generate__JI
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits)
{
  static const char * functionName = "NativeInterface.ECKEY_generate(size)";
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
  static char * curveOids[] =    { "1.2.840.10045.3.1.1",       /* P-192 */
   										"1.3.132.0.33",              /* P-224 */
   										"1.2.840.10045.3.1.7",       /* P-256 */
   										"1.3.132.0.34",              /* P-384 */
   										"1.3.132.0.35"              /* P-521 */
   										};
#ifdef __MVS__
  #pragma convert(pop)
#endif
  int           curveidx = 2;
  jlong         ecKeyId = 0;
  int           nid=0;
  int           rc = 0;
  const ICC_EC_GROUP *ockECGroup=NULL;

  
  ICC_CTX * ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *ockECKey = NULL;


  if( debug ) {
    gslogFunctionEntry(functionName);
  }
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC numBits=%d", numBits); 
  }
#endif
  switch (numBits) {
      case 192:
          curveidx=0;
          break;
      case 224:
          curveidx=1;
          break;
      case 256:
          curveidx=2;
          break;
      case 384:
          curveidx=3;
          break;
      case 521:
          curveidx=4;
          break;
      default:
         curveidx = 2;
      break;
  }
#ifdef DEBUG_EC_DETAIL
  if (debug) { 
    gslogMessage("DETAIL_EC curveOid %s", curveOids[curveidx]);
  }
#endif
  nid = ICC_OBJ_txt2nid (ockCtx, curveOids[curveidx]);
  if (nid == 0) {
    ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) { 
      gslogMessage("DETAIL_EC FAILURE ICC_OBJ_txt2nid");
    }
#endif
    throwOCKException(env, 0, "ICC_EC_Generate_key(ICC_OBJ_txt2nid) failed");
  }
  else {
#ifdef DEBUG_EC_DETAIL
    if (debug) { 
      gslogMessage ("DETAIL_EC nid %d", nid);
    }
#endif
    ockECKey = ICC_EC_KEY_new_by_curve_name (ockCtx, nid);
    if (ockECKey == NULL) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) { 
      gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_new_by_curve_name");
    }
#endif
      throwOCKException(env, 0, "ICC_EC_Generate_key(ICC_EC_KEY_new_by_curve_name) failed");
    }
    else {
      /* add generate key */
      rc = ICC_EC_KEY_generate_key (ockCtx, ockECKey);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC rc from ICC_EC_generate_key=%d", (int) rc);
        }
#endif
      if (rc != 1) {
  	ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) { 
      gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_generate_key rc=%d", rc);
    }
#endif
        throwOCKException(env, 0, "ICC_EC_Generate_key (ICC_EC_KEY_generate) failed");
      }
      else {
  
        ockECGroup = ICC_EC_KEY_get0_group(ockCtx, ockECKey);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC ockECGroup=%lx", (long) ockECGroup);
        }
#endif
        if (ockECGroup != NULL)
        {
          ICC_EC_GROUP_set_asn1_flag (ockCtx, (ICC_EC_GROUP *)ockECGroup, 1);
        }
        ecKeyId = (jlong)((intptr_t)ockECKey);                
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC returning ecKeyId=%lx", ecKeyId);
        }
#endif
        //rc = ICC_EC_KEY_check_key (ockCtx, ockECKey);
        //if (rc == 0) {
  	//      if( ockECKey != NULL) {
    	//    ICC_EC_KEY_free(ockCtx, ockECKey);
    	//    ockECKey = NULL;
  	//      }
  	//      ecKeyId = 0;
 	//      throwOCKException(env, 0, "ICC_EC_Generate_key (ICC_EC_KEY_check_key) failed");
        //} 
        //else {
         
          /* Do not attempt to release the ockECGroup 
          It is not a new structure
          if (ockECGroup != NULL) {
            ICC_EC_GROUP_free(ockCtx, (ICC_EC_GROUP *)ockECGroup);
            ockECGroup = NULL;
          }*/
          
          if( debug ) {
            gslogFunctionExit(functionName);
          }
          return ecKeyId;
        //} 
      }
    }
  }

  if( (ockECKey != NULL) && (ecKeyId == 0) ) {
    ICC_EC_KEY_free(ockCtx, ockECKey);
    ockECKey = NULL;
  }
  /* Do not attempt to release the ockECGroup 
  It is not a new structure
  if (ockECGroup != NULL) {
     ICC_EC_GROUP_free(ockCtx, (ICC_EC_GROUP *)ockECGroup);
     ockECGroup = NULL;
  }*/  
  if( debug ) {
    gslogFunctionExit(functionName);
  }
  return (jlong)0;
}
//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_1generate__JLjava_lang_String_2 
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1generate__JLjava_lang_String_2 
(JNIEnv *env, jclass thisObj, jlong ockContextId, jstring soid)
{
  static const char * functionName = "NativeInterface.ECKEY_generate(soid)";
  jlong               ecKeyId = 0;
  int                 nid=0;
  int                 rc = 0;
  const ICC_EC_GROUP *ockECGroup = NULL;

  ICC_CTX * ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *ockECKey = NULL;
 /* const jbyte *nativeSoid=NULL;*/
  const char *nativeSoid=NULL;
  
  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (soid == NULL) {
    throwOCKException(env, 0, "ECKey generate the specified input parameters are incorrect.");
    if( debug ) {
      gslogFunctionExit(functionName);
    }
    return ecKeyId;
  }
  nativeSoid = (*env)->GetStringUTFChars(env, soid, NULL);
  if (nativeSoid == NULL) {
#ifdef DEBUG_EC_DETAIL
    if (debug) { 
      gslogMessage("DETAIL_EC FAILURE nativeSoid");
    }
#endif
      throwOCKException(env, 0, "ICC_EC_Generate_key (GetStringUTFChars) failed");
  } 
  else {
#ifdef DEBUG_EC_DETAIL
    if( debug ) {
      gslogMessage ("DETAIL_EC soid=%s", nativeSoid);
    }
#endif
    nid = ICC_OBJ_txt2nid (ockCtx, (char *) nativeSoid);
    if (nid <= 0) {
      (*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE ICC_OBJ_txt2nid");
    }
#endif

      throwOCKException(env, 0, "ICC_EC_Generate_key(ICC_OBJ_txt2nid) failed");
    }
    else {
#ifdef DEBUG_EC_DETAIL      
      if (debug ) {
        gslogMessage ("DETAIL_EC nid=%d", nid);
      }  
#endif
      ockECKey = ICC_EC_KEY_new_by_curve_name (ockCtx, nid);
      if (ockECKey == NULL) {
        (*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
        ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_new_by_curve_name");
        }
#endif

        throwOCKException(env, 0, "ICC_EC_Generate_key(ICC_EC_KEY_new_by_curve_name) failed");
      }
      else {
        /* add generate key */
        rc = ICC_EC_KEY_generate_key (ockCtx, ockECKey);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC rc from ICC_EC_KEY_generate_key  %d", rc);
        }
#endif
        if (rc != 1) {
  	      (*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
  	      nativeSoid = NULL;
  	      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
              if (debug) {
                gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_generate_key %d", rc);
              }
#endif

          throwOCKException(env, 0, "ICC_EC_Generate_key (ICC_EC_KEY_generate) failed");
        }
        else {
  
          ockECGroup = ICC_EC_KEY_get0_group(ockCtx, ockECKey);
          if (ockECGroup != NULL)
          {
#ifdef DEBUG_EC_DETAIL
            if ( debug ) {
              gslogMessage ("DETAIL_EC ockECGroup %lx", (long) ockECGroup);
            }
#endif
            ICC_EC_GROUP_set_asn1_flag (ockCtx, (ICC_EC_GROUP *)ockECGroup, 1);
          }
          else {
#ifdef DEBUG_EC_DETAIL
            if ( debug ) {
              gslogMessage ("ockECGroup is null");
            }
#endif
          }
  
          ecKeyId = (jlong)((intptr_t)ockECKey);
#ifdef DEBUG_EC_DETAIL
          if( debug ) {
            gslogMessage("DETAIL_EC ecKeyId=%lx", ecKeyId);
          } 
#endif
          (*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
          //rc = ICC_EC_KEY_check_key (ockCtx, ockECKey);
          //if (rc == 0) {
	  //      if( ockECKey != NULL) {
    	  //    ICC_EC_KEY_free(ockCtx, ockECKey);
  	  //      }
  	  //      ecKeyId = 0;
 	  //      throwOCKException(env, 0, "ICC_EC_Generate_key (ICC_EC_KEY_check_key) failed");
          //}
          //else
          //{
            
            if( (ockECKey != NULL) && (ecKeyId == 0) ) {
              ICC_EC_KEY_free(ockCtx, ockECKey);
              ockECKey = NULL;
            }
            /* Do not attempt to release the ockECGroup 
               It is not a new structure
            if (ockECGroup != NULL) {
              ICC_EC_GROUP_free(ockCtx, (ICC_EC_GROUP *)ockECGroup);
              ockECGroup = NULL;
            }*/ 
            if( debug ) {
              gslogFunctionExit(functionName);
            } 
            return ecKeyId;
          //}
        }
      }
    }
  }
   /* Do not attempt to release the ockECGroup 
  It is not a new structure
  if (ockECGroup != NULL) {
     ICC_EC_GROUP_free(ockCtx, (ICC_EC_GROUP *)ockECGroup);
     ockECGroup = NULL;
  }*/  
  
  
  if( (ockECKey != NULL) && (ecKeyId == 0) ) {
    ICC_EC_KEY_free(ockCtx, ockECKey);
    ockECKey = NULL;
  }
  if( debug ) {
    gslogFunctionExit(functionName);
  }
  return (jlong) 0; //Satisfy the compiler warning
}

// helper fuction for XECKEY_generate
int getPublicKey(ICC_CTX *ockCtx, JNIEnv *env, ICC_EVP_PKEY *key, unsigned char* buffer) {
  size_t pub_size;
  int rc;

  ICC_EVP_PKEY_get_raw_public_key(ockCtx, key, NULL, &pub_size);
  rc = ICC_EVP_PKEY_get_raw_public_key(ockCtx, key, buffer, &pub_size); /* Add public key */

  return (rc == 1) ? rc : -1;
}

// helper fuction for XECKEY_generate
int getDERPublicKey(ICC_CTX *ockCtx, JNIEnv *env, ICC_EVP_PKEY *key, unsigned char* buffer) {
  unsigned char* p = NULL;
  int rc = 0;

  p = buffer;
  rc = ICC_i2d_PUBKEY(ockCtx, key, &p);
  return rc;
}

// helper fuction for XECKEY_generate
int getOption(int option) {
  switch (option) {
    case 0: return NID_X25519;
    case 1: return NID_X448;
    case 2: return NID_ffdh;
    case 3: return NID_ffdh;
    case 4: return NID_ffdh;
    case 5: return NID_ffdh;
    case 6: return NID_ffdh;
    case 7: return NID_ED25519;
    case 8: return NID_ED448;
  }
  return -1;
}

// helper fuction for XECKEY_generate
char* getFFDHOption(int option) {
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
  switch (option) {
    case 2: return "ffdhe2048";
    case 3: return "ffdhe3072";
    case 4: return "ffdhe4096";
    case 5: return "ffdhe6144";
    case 6: return "ffdhe8192";
  }
  return NULL;
#ifdef __MVS__
  #pragma convert(pop)
#endif
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_generate
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1generate
(JNIEnv *env, jclass thisObj, jlong ockContextId, jint option, jlong bufferPtr)
{
  static const char * functionName = "XECKEY_generate";
  ICC_CTX *           ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY *      key = NULL;
  char*               secondaryOption = NULL;
  ICC_EVP_PKEY_CTX*   pctx = NULL;
  int                 rc = 0;
  int                 mainOption = 0;

  if(debug) gslogFunctionEntry(functionName);

  if ((unsigned char *) bufferPtr == NULL) {
    throwOCKException(env, 0, "XECKEY generate The specified input parameters are not correct.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return -1;
  }

  mainOption = getOption(option);
  if(mainOption > 0) {    
    pctx = ICC_EVP_PKEY_CTX_new_id(ockCtx, mainOption, NULL);
    if(pctx != NULL) {
      if(mainOption == NID_ffdh) {
        secondaryOption = getFFDHOption(option);
        if(secondaryOption == NULL) goto errorCode;
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
        rc = ICC_EVP_PKEY_CTX_ctrl_str(ockCtx, pctx, "dh_param",secondaryOption);
#ifdef __MVS__
  #pragma convert(pop)
#endif
        if(rc != 1) goto errorCode;
      }
      rc = ICC_EVP_PKEY_keygen_init(ockCtx, pctx);
      if (rc == 1) {
        rc = ICC_EVP_PKEY_keygen(ockCtx, pctx, &key);
        if (rc == 1) {
          if(mainOption == NID_ffdh) rc = getDERPublicKey(ockCtx, env, key, (unsigned char*) bufferPtr);
          else rc = getPublicKey(ockCtx, env, key, (unsigned char*) bufferPtr);
          if (rc > 0) {
            if(debug) gslogFunctionExit(functionName);
            if (pctx != NULL) {
              ICC_EVP_PKEY_CTX_free(ockCtx, pctx);
              pctx = NULL;
            }
            return (jlong)((intptr_t)key);
          }
        }
      }
      if (pctx != NULL) {
        ICC_EVP_PKEY_CTX_free(ockCtx, pctx);
    	pctx = NULL;
      }
    }
  }
  errorCode:
  if(debug) gslogFunctionExit(functionName);
  throwOCKException(env, 0, "Error occured in XECKEY_generate");
  return -1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_1generateParameters__JI
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1generateParameters__JI
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits)
{
  static const char * functionName = "NativeInterface.ECKEY_1generateParameters";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *    ockECKey = NULL;
  jbyteArray      parmBytes = NULL;
  unsigned char * parmBytesNative = NULL;
  jboolean        isCopy = 0;
  jbyteArray      retParmBytes = NULL;
  unsigned char * pBytes = NULL;
  
#ifdef __MVS__
  #pragma convert("ISO8859-1")
#endif
  static char *   curveNames[] = {"prime192v1", "prime224v1", "prime256v1", "prime384v1", "prime581v1"};
#ifdef __MVS__
  #pragma convert(pop)
#endif
  int             curveidx = 2;
  int             size = 0;
  int             nid;
  
  if( debug ) {
    gslogFunctionEntry(functionName);
  }

#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC numBits=%d", numBits);
  }
#endif
  switch (numBits) {
      case 192:
          curveidx=0;
          break;
      case 224:
          curveidx=1;
          break;
      case 256:
          curveidx=2;
          break;
      case 384:
          curveidx=3;
          break;
      case 581:
          curveidx=4;
          break;
      default:
         curveidx = 2;
      break;
  }

#ifdef DEBUG_EC_DETAIL
  if ( debug ) {
    gslogMessage ("DETAIL_EC curveidx=%d curveName=%s", curveidx, curveNames[curveidx]);
  }
#endif
  
  nid = ICC_OBJ_txt2nid (ockCtx, curveNames[curveidx]);
  if (nid == 0) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE ICC_OBJ_txt2nid");
    }
#endif

      throwOCKException(env, 0, "ICC_EC_Generate_key(ICC_OBJ_txt2nid) failed");
  }
  else
  {
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC nid=%d", nid);
    }
#endif
    ockECKey = ICC_EC_KEY_new_by_curve_name (ockCtx, nid);
    if (ockECKey == NULL) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_new_by_curve_name");
      }
#endif

      throwOCKException(env, 0, "ICC_EC_Generate_key failed");
    }
    else
    {
      size = ICC_i2d_ECParameters (ockCtx, ockECKey, NULL);
#ifdef DEBUG_EC_DETAIL 
      if ( debug ) {
        gslogMessage ("DETAIL_EC ockECKey=%lx", (long) ockECKey);
        gslogMessage ("DETAIL_EC size from ICC_i2d_ECParameters=%d", size);
      }
#endif
  
      if( size < 0 ) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECParameters");
        }
#endif
        throwOCKException(env, 0, "ICC_i2d_ECParameters failed");
      } else {
        parmBytes = (*env)->NewByteArray(env, size);
        if( parmBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE parmBytes");
          }
#endif
          throwOCKException(env, 0, "NewByteArray failed");
        } else {
          parmBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, parmBytes, &isCopy));
          if( parmBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
            if (debug) {
              gslogMessage("DETAIL_EC FAILURE parmBytesNative");
            }
#endif
            throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
          } 
          else 
          {
            pBytes = (unsigned char *)parmBytesNative;

            size = ICC_i2d_ECParameters (ockCtx, ockECKey, &pBytes);
            if( size <= 0 ) {
              ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
              if (debug) {
                gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECParameters %d", size);
              }
#endif
              throwOCKException(env, 0, "ICC_i2d_ECParameters failed");
            }
            else {
              retParmBytes = parmBytes;
#ifdef DEBUG_EC_DATA
              if ( debug ) {
                gslogMessage ("DATA_EC size from ICC_i2d_ECParameters(2) =%d", size);
                gslogMessagePrefix("DATA_EC parmBytes : ");
                gslogMessageHex ((char *) parmBytes, 0, size, 0, 0, NULL);
              }
#endif
            }
          }
        }
      }
    }
  }

  if( ockECKey != NULL ) {
    ICC_EC_KEY_free(ockCtx, ockECKey);
    ockECKey = NULL;
  }

  if( parmBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative, 0);
  }

  if( (parmBytes != NULL) && (retParmBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, parmBytes);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return retParmBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_1generateParameters__JLjava_lang_String_2
 * Signature: (JLjava/lang/String;)[B
 */
 JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1generateParameters__JLjava_lang_String_2
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring soid)
{
  static const char * functionName = "ECKEY_1generateParameters__JLjava_lang_String_2";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *    ockECKey = NULL;
  jbyteArray      parmBytes = NULL;
  unsigned char * parmBytesNative = NULL;
  jboolean        isCopy = 0;
  jbyteArray      retParmBytes = NULL;
  /*const jbyte *nativeSoid=NULL;*/
  const char *    nativeSoid=NULL;  
  int             size = 0;
  int             nid;
  
  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (soid == NULL) {
    throwOCKException (env, 0, "Generating EC parameters failed. The specified input parameter is incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return retParmBytes;
  }
  nativeSoid = (*env)->GetStringUTFChars(env, soid, NULL);
  if (nativeSoid == NULL) {
       /* fprintf (stderr, "Could not allocate NativeSoid\n");
  		fflush (stderr); */
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE nativeSoid");
    }
#endif

      throwOCKException(env, 0, "ICC_EC_Generate_Parameters (GetStringUTFChars) failed");
  } 
  else 
  {
#ifdef DEBUG_EC_DETAIL
    if( debug ) {
      gslogMessage ("DETAIL_EC soid=%s", nativeSoid);
    }
#endif
    nid = ICC_OBJ_txt2nid (ockCtx, (char  *) nativeSoid );
#ifdef DEBUG_EC_DETAIL
    if ( debug ) { 
      gslogMessage ("DETAIL_EC nid=%d", nid);
    }
#endif
    if (nid <= 0) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE nid %d", nid);
      }
#endif
      throwOCKException(env, 0, "ICC_EC_Generate_Parameters(ICC_OBJ_txt2nid) failed");
    }
    else
    {
      ockECKey = ICC_EC_KEY_new_by_curve_name (ockCtx, nid);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) { 
        gslogMessage ("DETAIL_EC ockECKey=%lx", (long) ockECKey);
      }
#endif
      if (ockECKey == NULL) {
        ockCheckStatus(ockCtx);
        //(*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE ICC_EC_Generate_key");
        }
#endif
        throwOCKException(env, 0, "ICC_EC_Generate_key failed");
      }
      else
      {
        size = ICC_i2d_ECParameters (ockCtx, ockECKey, NULL);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) { 
          gslogMessage ("DETAIL_EC size from ICC_i2d_ECParameters =%d", size);
        }
#endif
  
        if( size < 0 ) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECParameters");
          }
#endif
          throwOCKException(env, 0, "ICC_i2d_ECParameters failed");
        } 
        else
        {
          parmBytes = (*env)->NewByteArray(env, size);
          if( parmBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
            if (debug) {
              gslogMessage("DETAIL_EC FAILURE parmBytes");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
          } 
          else 
          {
            parmBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, parmBytes, &isCopy));
            if( parmBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
              if (debug) {
                gslogMessage("DETAIL_EC FAILURE parmBytesNative");
              }
#endif
              throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
            } 
            else 
            {
              unsigned char * pBytes = (unsigned char *)parmBytesNative;

              size = ICC_i2d_ECParameters (ockCtx, ockECKey, &pBytes);
#ifdef EC_DEBUG
              if ( debug ) { 
                gslogMessage ("DETAIL_EC size from ICC_i2d_ECParameters(2) =%d", size);
              }
#endif
              if( size <= 0 ) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
                if (debug) {
                  gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECParameters size %d", size);
                }
#endif
                //(*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
                throwOCKException(env, 0, "ICC_i2d_ECParameters failed");
              } 
              else 
              {
                retParmBytes = parmBytes;
#ifdef DEBUG_EC_DATA
                if( debug ) {
                  gslogMessagePrefix("DATA_EC parmBytes : ");
                  gslogMessageHex ( (char *) parmBytes, 0, size, 0, 0, NULL);
                  gslogFunctionExit(functionName);
                }
#endif
              }
            }
          }
        }
      }
    }
  }
  

  if( ockECKey != NULL ) {
    ICC_EC_KEY_free(ockCtx, ockECKey);
    ockECKey = NULL;
  }

  if( parmBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative, 0);
  }

  if( (parmBytes != NULL) && (retParmBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, parmBytes);
  }
  if (nativeSoid != NULL) {
    (*env)->ReleaseStringUTFChars (env, soid, nativeSoid);
  }
  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return retParmBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_generate
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1generate__J_3B
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray parameterBytes)
{
  static const char * functionName = "NativeInterface.ECKEY_generate__J_3B";

  ICC_CTX *             ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  unsigned char *       parameterBytesNative = NULL;
  jboolean              isCopy = 0;
  ICC_EC_KEY *          ockECKey = NULL;
  jlong                 ecKeyId = 0;
  int                   rc = 0;
  jint                  size;
  const unsigned char * pBytes;
  

  if( debug ) {
     gslogFunctionEntry(functionName);
  }

  if (parameterBytes == NULL) {
    throwOCKException(env, 0, "The specified input parameters are incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return ecKeyId;
  }
  parameterBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, parameterBytes, &isCopy));
  if (parameterBytesNative == NULL) {
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE paramBytesNative");
    }
#endif
   	throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  }
  else 
  {  
    size = (*env)->GetArrayLength(env, parameterBytes);
    pBytes = (const unsigned char *)parameterBytesNative;
#ifdef DEBUG_EC_DATA
    if ( debug ) { 
      gslogMessage ("DATA_EC parameter size %d\n", (int)size);
      gslogMessagePrefix("DATA_EC parameterBytes : ");
      gslogMessageHex( (char *) pBytes, 0, size, 0, 0, NULL);
    }
#endif
    ockECKey = ICC_EC_KEY_new (ockCtx);
    if (ockECKey == NULL ) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_new ");
      }
#endif

      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "NULL from ICC_EC_KEY_new");
    }
    else
    {
 	  //ockECGroup = ICC_d2i_ECPKParameters (ockCtx, NULL, &pBytes, size);
  	  ockECKey = ICC_d2i_ECParameters (ockCtx, NULL, &pBytes, size);
#ifdef DEBUG_EC_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_EC ockECKey=%lx\n", (long)ockECKey);
          }
#endif
  	  if( ockECKey == NULL ) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
            if (debug) {
              gslogMessage("DETAIL_EC FAILURE ICC_d2i_ECParameters");
            }
#endif

      	    throwOCKException(env, 0, "NULL from ICC_d2i_ECPKParameters");
  	  } 
      else
  	  {
  	    /* add generate key */
  		rc = ICC_EC_KEY_generate_key (ockCtx, ockECKey);
#ifdef DEBUG_EC_DETAIL
                if ( debug ) {
                  gslogMessage ("DETAIL_EC rc from ICC_EC_KEY_generate_key=%d", rc);
                }
#endif
 		if (rc != 1) {
  	 	  //(*env)->ReleasePrimitiveArrayCritical(env, parameterBytes, parameterBytesNative, 0);
  	          ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
                  if (debug) {
                    gslogMessage("DETAIL_EC FAILURE ICC)+EC_KEY_generate_key %d", rc);
                  }
#endif
      	          throwOCKException(env, 0, "ICC_EC_Generate_key (ICC_EC_KEY_generate) failed");
  		}
  		else
  		{
 		  ecKeyId = (jlong)((intptr_t)ockECKey);
#ifdef DEBUG_EC_DETAIL
                  if ( debug ) {
                    gslogMessage ("DETAIL_EC ecKeyId=%lx", ecKeyId);
                  }
#endif
 	        }
 	      
 	  } 
 	}     
  }   
  if (parameterBytesNative != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, parameterBytes, parameterBytesNative, 0);
  }
  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return ecKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1createPrivateKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray privateKeyBytes)
{
  static const char * functionName = "NativeInterface.ECKEY_createPrivateKey";

  ICC_CTX *             ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *          ockECKey = NULL;
  unsigned char *       keyBytesNative = NULL;
  jboolean              isCopy = 0;
  jlong                 ecKeyId = 0;
  const unsigned char * pBytes;
  jint                  size;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (privateKeyBytes == NULL ) {
    throwOCKException(env, 0, "Creating EC Private Key failed. The specified input parameters are incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return ecKeyId;
  }
  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  if( keyBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } 
  else 
  {
    pBytes = (const unsigned char *)keyBytesNative;
    size = (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_EC_DATA
    if ( debug ) {
      gslogMessage ("DATA_EC size=%d", (int) size);
      gslogMessagePrefix ("DATA_EC privateKeyBytes : ");
      gslogMessageHex ((char *)  pBytes, 0, size, 0, 0, NULL);
   }
#endif
    

    ockECKey = ICC_d2i_ECPrivateKey(ockCtx, NULL, &pBytes, (long)size);
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC ockECKey=%lx", (long) ockECKey);
    }
#endif
    if( ockECKey == NULL ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE ICC_d2i_ECPrivateKey");
      }
#endif
      throwOCKException(env, 0, "ICC_d2i_ECPrivateKey failed");
    } 
    else {
      ecKeyId = (jlong)((intptr_t)ockECKey);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) {
        gslogMessage ("DETAIL_EC returning ecKeyId=%lx", ecKeyId);
      }
#endif
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes, keyBytesNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  /* fprintf (stderr, "Return OCK ecKeyId %lx\n", ecKeyId);*/
  
  /*	rc = ICC_EC_KEY_check_key (ockCtx, ockECKey);
        fprintf (stderr, "validate key %d\n", rc);
  	    if (rc == 0)
 		   throwOCKException(env, 0, "ICC_EC_Generate_key (ICC_EC_KEY_check_key) failed"); */
 		   
  return ecKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1createPrivateKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray privateKeyBytes, jlong bufferPtr)
{
  static const char * functionName = "NativeInterface.XECKEY_createPrivateKey";

  ICC_CTX *             ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
  ICC_EVP_PKEY *        ockEVPKey = NULL;
  unsigned char *       keyBytesNative = NULL;
  const unsigned char * pBytes = NULL;
  jboolean              isCopy = 0;
  jlong                 xecKeyId = 0;
  size_t                size;

  if( debug ) gslogFunctionEntry(functionName);

  if ((privateKeyBytes == NULL) || ((unsigned char *) bufferPtr == NULL) ) {
    throwOCKException(env, 0, "Creating XEC Private Key failed. The specified input parameters are incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return  xecKeyId;
  }
  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  
  if( keyBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_XEC FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } 
  else {
    pBytes = (const unsigned char *)keyBytesNative;
    size = (size_t) (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_EC_DATA
    if ( debug ) {
      gslogMessage ("DATA_XEC size=%d", (int) size);
      gslogMessagePrefix ("DATA_EC privateKeyBytes : ");
      gslogMessageHex ((char*) pBytes, 0, size, 0, 0, NULL);
   }
#endif
    ICC_d2i_PrivateKey(ockCtx, ICC_EVP_PKEY_EC, &ockEVPKey, (unsigned char**) &pBytes, (long)size);
#ifdef DEBUG_EC_DETAIL
    if ( debug ) gslogMessage ("DETAIL_XEC ockEVPKey=%lx", (long) ockEVPKey);
#endif
    if( ockEVPKey == NULL ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE ICC_d2i_PrivateKey");
      }
#endif
      throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
    } 
    else {
      xecKeyId = (jlong)((intptr_t)ockEVPKey);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) gslogMessage ("DETAIL_XEC returning xecKeyId=%lx", xecKeyId);
#endif
      ICC_EVP_PKEY_get_raw_public_key(ockCtx, ockEVPKey, (unsigned char*) bufferPtr, &size);
    }
  }

  if( keyBytesNative != NULL ) (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes, keyBytesNative, 0);
  if( debug ) gslogFunctionExit(functionName);
  return xecKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1createPublicKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray publicKeyBytes, jbyteArray parameterBytes)
{
  static const char * functionName = "NativeInterface.ECKEY_createPublicKey";

  ICC_CTX *        ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *     ockECKey = NULL;
  unsigned char *  keyBytesNative = NULL;
  unsigned char *  parameterBytesNative = NULL;
  jboolean         isCopy = 0;
  jlong            ecKeyId = 0;
  unsigned char *  pKeyBytes = NULL;
  unsigned char *  pParamBytes = NULL;
  jint             size = 0;
  jint             paramsize = 0; 

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if ( (publicKeyBytes == NULL) || (parameterBytes == NULL)) {
    throwOCKException(env, 0, "Creating EC Public Key failed. The specified input parameters are incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return ecKeyId;
  }

  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, &isCopy));
  if( keyBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  }
  else 
  { 
    parameterBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, parameterBytes, &isCopy));
    if (parameterBytesNative == NULL) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE parameterBytesNative");
      }
#endif
   	  throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  	}
  	else 
  	{
      pKeyBytes = (unsigned char *)keyBytesNative;
      size = (*env)->GetArrayLength(env, publicKeyBytes);
	  pParamBytes = (unsigned char *)parameterBytesNative;
      paramsize = (*env)->GetArrayLength(env, parameterBytes);
#ifdef DEBUG_EC_DATA
      if ( debug ) {
        gslogMessage ("DATA_EC size=%d", (int) size);
        gslogMessagePrefix ("DATA_EC publicKeyBytes : ");
        gslogMessageHex ((char *)  pKeyBytes, 0, size, 0, 0, NULL);
      }
#endif
      
      ockECKey = ICC_d2i_ECParameters(ockCtx, &ockECKey, (const unsigned char **) &pParamBytes, (long)paramsize);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) {
          gslogMessage ("DETAIL_EC ockECKey from ICC_d2i_ECParameters=%lx", (long) ockECKey);
      }
#endif
      if (ockECKey == NULL) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE ICC_d2i_ECParameters");
        }
#endif
      	throwOCKException(env, 0, "ICC_d2i_ECParameters failed");
      }
      else
      {
        ockECKey = ICC_o2i_ECPublicKey(ockCtx, &ockECKey, &pKeyBytes, (long)size);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC ockECKey from ICC_o2i_ECPublicKey=%lx", (long) ockECKey);
        }
#endif
    	if( ockECKey == NULL ) {
      	  ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE ICC_o2i_ECPublicKey");
          }
#endif
      	  throwOCKException(env, 0, "ICC_o2i_ECPublicKey failed");
    	} 
    	else 
    	{
      	  ecKeyId = (jlong)((intptr_t)ockECKey);
#ifdef DEBUG_EC_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_EC ecKeyId=%lx", (long) ecKeyId);
          }
#endif
    	}
      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes, keyBytesNative, 0);
  }

  if( parameterBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, parameterBytes, parameterBytesNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return ecKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1createPublicKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray publicKeyBytes)
{
  static const char * functionName = "NativeInterface.XECKEY_createPublicKey";

  ICC_CTX *        ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY *   ockEVPKey = NULL;
  unsigned char *  keyBytesNative = NULL;
#ifdef DEBUG_EC_DATA
  unsigned char *  pBytes = NULL;
#endif  
  unsigned char *  ptr = NULL;
  jboolean         isCopy = 0;
  jlong            xecKeyId = 0;
  jint             size;

  if( debug ) gslogFunctionEntry(functionName);

  if (publicKeyBytes == NULL) {
    throwOCKException(env, 0, "Creating XEC Public Key failed. The specified input parameters are incorrect.");
	if ( debug ) {
	  gslogFunctionExit(functionName);
	}
	return  xecKeyId;
  }

  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, &isCopy));
  if( keyBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) gslogMessage("DETAIL_XEC FAILURE keyBytesNative");
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  }
  else {
    size = (*env)->GetArrayLength(env, publicKeyBytes);
#ifdef DEBUG_EC_DATA
    pBytes = (unsigned char *)keyBytesNative;
    if ( debug ) {
     
      gslogMessagePrefix ("DATA_XEC publicKeyBytes : ");
      gslogMessageHex ((char*) pBytes, 0, size, 0, 0, NULL);
    }
#endif
    ptr = keyBytesNative;
    ICC_d2i_PUBKEY(ockCtx, &ockEVPKey, (const unsigned char **) &ptr, size);
#ifdef DEBUG_EC_DETAIL
    if ( debug ) gslogMessage ("DETAIL_XEC ockEVPKey from ICC_d2i_PUBKEY=%lx", (long) ockEVPKey);
#endif
    if( ockEVPKey == NULL ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
      if (debug) gslogMessage("DETAIL_XEC FAILURE ICC_d2i_XDHPublicKey");
#endif
      throwOCKException(env, 0, "ICC_d2i_XDHPublicKey failed");
    } 
    else {
      xecKeyId = (jlong)((intptr_t)ockEVPKey);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) gslogMessage ("DETAIL_XEC xecKeyId=%lx", (long) xecKeyId);
#endif
    }
  }

  if( keyBytesNative != NULL ) (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes, keyBytesNative, 0);
  if( debug ) gslogFunctionExit(functionName);

  return xecKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_getParameters
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1getParameters
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ecKeyId)
{
  static const char * functionName = "NativeInterface.ECKEY_getParameters";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *    ockECKey = (ICC_EC_KEY *)((intptr_t) ecKeyId);
  jbyteArray      parmBytes = NULL;
  unsigned char * parmBytesNative = NULL;
  unsigned char * pBytes = NULL;
  jboolean        isCopy = 0;
  int             size = 0;
  jbyteArray      retParmBytes = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (ockECKey == NULL) {
    throwOCKException(env, 0, "EC Key getting parameters failed. The specified input parameters are incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return retParmBytes;
  }
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC ockECKey=%lx", (long) ockECKey);
    }
#endif
  size = ICC_i2d_ECParameters (ockCtx, ockECKey, NULL);
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC ECParameters size=%d", size);
  }
#endif
  if( size < 0 ) {
    ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECParameters %d", size);
    }
#endif
    throwOCKException(env, 0, "ICC_i2d_ECparameters failed");
  } else {
    parmBytes = (*env)->NewByteArray(env, size);
    if( parmBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE parmBytes");
      }
#endif

      throwOCKException(env, 0, "NewByteArray failed");
    } 
    else 
    {
      parmBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, parmBytes, &isCopy));
      if( parmBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE parmBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } 
      else 
      {
        pBytes = (unsigned char *)parmBytesNative;

        size = ICC_i2d_ECParameters (ockCtx, ockECKey, &pBytes);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
            gslogMessage ("DETAIL_EC size %d=", size);
        }
#endif
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECParmeters size=%d", size);
          }
#endif
          throwOCKException(env, 0, "ICC_i2d_ECParameters failed");
        } else {
          retParmBytes = parmBytes;
#ifdef DEBUG_EC_DATA
          if ( debug ) {
            gslogMessagePrefix ("DATA_EC Parameter bytes : ");
            gslogMessageHex ( (char *) pBytes, 0, size, 0, 0, NULL);
          }
#endif
        }
      }
    }
  }

  if( parmBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative, 0);
  }

  if( (parmBytes != NULL) && (retParmBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, parmBytes);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
  return retParmBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1getPrivateKeyBytes
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong ecKeyId)
{
  static const char * functionName = "NativeInterface.ECKEY_getPrivateKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *    ockECKey = (ICC_EC_KEY *)((intptr_t) ecKeyId);
  jbyteArray      keyBytes = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  int             size;
  jbyteArray      retKeyBytes = NULL;
  unsigned char * pBytes = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }


  if (ockECKey == NULL) {
    throwOCKException(env, 0, "The specified EC Key identifier is incorrect.");
	if( debug ) {
      gslogFunctionExit(functionName);
	}
	return retKeyBytes;
  }

#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC ockECKey=%lx", (long) ockECKey);
  }
#endif

  size = ICC_i2d_ECPrivateKey(ockCtx, ockECKey, NULL);
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC size from ICC_i2d_ECPrivateKey=%d", size);
  }
#endif
  if( size <= 0 ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_i2d_ECPrivateKey failed");
  } 
  else 
  {
    keyBytes = (*env)->NewByteArray(env, size);
    if( keyBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE keyBytes");
      }
#endif

      throwOCKException(env, 0, "NewByteArray failed");
    } 
    else 
    {
      keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
      if( keyBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE keyBytesNative");
      }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } 
      else 
      {
        pBytes = (unsigned char *)keyBytesNative;

        size = ICC_i2d_ECPrivateKey(ockCtx, ockECKey, &pBytes);
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE ICC_i2d_ECPrivateKey size %d", size);
          }
#endif
          throwOCKException(env, 0, "ICC_i2d_ECPrivateKey failed");
        } 
        else 
        {
          retKeyBytes = keyBytes;
#ifdef DEBUG_EC_DATA
          if ( debug ) {
              gslogMessage ("DATA_EC size from ICC_i2d_ECPrivateKey %d", (int) size);
              gslogMessagePrefix ("DATA_EC keyBytes : ");
              gslogMessageHex ((char *)  pBytes, 0, size, 0, 0, NULL);
          }
#endif
        }
      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
  }

  if( (keyBytes != NULL) && (retKeyBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, keyBytes);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
  return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1getPrivateKeyBytes
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong xecKeyId)
{
  static const char * functionName = "NativeInterface.XECKEY_getPrivateKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
  ICC_EVP_PKEY *  ockEVPKey = (ICC_EVP_PKEY *)((intptr_t)xecKeyId);
  unsigned char * keyBytesNative = NULL;
  jbyteArray      keyBytes = NULL;
  jbyteArray      retKeyBytes = NULL;
  unsigned char * pBytes = NULL;
  int             size;
  jboolean        isCopy = 0;

  if (ockEVPKey == NULL) {
    throwOCKException(env, 0, "XEC Key getting Private Key bytes failed. The specified input parameters are incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return retKeyBytes;
  }
  size = ICC_i2d_PrivateKey(ockCtx, ockEVPKey, NULL);
  keyBytes = (*env)->NewByteArray(env, size);
  if(keyBytes != NULL) {
    keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
    if(keyBytesNative != NULL) {
      pBytes = (unsigned char *)keyBytesNative;
      size = ICC_i2d_PrivateKey(ockCtx, ockEVPKey, &pBytes);
      retKeyBytes = keyBytes;
      (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
      return retKeyBytes;
    }
    (*env)->DeleteLocalRef(env, keyBytes);
  }
  return 0;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1getPublicKeyBytes
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ecKeyId )
{
  static const char * functionName = "NativeInterface.ECKEY_getPublicKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *    ockECKey = (ICC_EC_KEY *)((intptr_t) ecKeyId);
  jbyteArray      keyBytes = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  int             size;
  jbyteArray      retKeyBytes = NULL;
  unsigned char * pBytes = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC ockECKey=%lx", (long) ockECKey);
  }
#endif

  size = ICC_i2o_ECPublicKey(ockCtx, ockECKey, NULL);
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC size from ICC_i20_ECPublicKey(NULL)=%d", (int) size);
  }
#endif
  if( size <= 0 ) {
    ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE size %d", size);
    }
#endif
    throwOCKException(env, 0, "ICC_i2o_ECPublicKey failed");
  } 
  else 
  {
    keyBytes = (*env)->NewByteArray(env, size);
    if( keyBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE keyBytes");
      }
#endif
      throwOCKException(env, 0, "NewByteArray failed");
    } 
    else 
    {
      keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
      if( keyBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE keyBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } 
      else 
      {
        pBytes = (unsigned char *)keyBytesNative;

        size = ICC_i2o_ECPublicKey(ockCtx, ockECKey, &pBytes);
#ifdef DEBUG_EC_DETAIL
        if( debug ) {
          gslogMessage ("DETAIL_EC size from ICC_i2o_ECPublicKey=%d", (int) size);
        }
#endif
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE ICC_i2o_ECPublicKey");
          }
#endif
          throwOCKException(env, 0, "ICC_i2o_ECPublicKey failed");
        } else {
#ifdef DEBUG_EC_DATA
          if ( debug ) {
              gslogMessagePrefix ("DATA_EC Public keyBytes : ");
              gslogMessageHex ((char *)  pBytes, 0, size, 0, 0, NULL);
          }
#endif
          retKeyBytes = keyBytes;
        }
      }
    }
  }

  if( (keyBytes != NULL) && (retKeyBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, keyBytes);
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return keyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */

JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1getPublicKeyBytes
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong xecKeyId )
{
  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
  ICC_EVP_PKEY *  ockEVPKey = (ICC_EVP_PKEY *)xecKeyId;
  unsigned char * keyBytesNative = NULL;
  jbyteArray      keyBytes = NULL;
  size_t          size;
  jboolean        isCopy = 0;

  ICC_EVP_PKEY_get_raw_public_key(ockCtx, ockEVPKey, NULL, &size);
  keyBytes = (*env)->NewByteArray(env, size);
  if(keyBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) gslogMessage("DETAIL_EC FAILURE keyBytes");
#endif
    throwOCKException(env, 0, "NewByteArray failed");
  } else {
    keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
    if( keyBytesNative == NULL ) {
  #ifdef DEBUG_EC_DETAIL
      if (debug) gslogMessage("DETAIL_EC FAILURE keyBytesNative");
  #endif
      throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
    } else {
      if(keyBytesNative != NULL) {
        ICC_EVP_PKEY_get_raw_public_key(ockCtx, ockEVPKey, keyBytesNative, &size);
        (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
      }
      if( (keyBytes != NULL) ) {
        (*env)->DeleteLocalRef(env, keyBytes);
      }
    }
  }
  return keyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1createPKey
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong ecKeyId)
{
  static const char * functionName = "NativeInterface.ECKEY_createPKey";

  ICC_CTX *      ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *   ockECKey = (ICC_EC_KEY *)((intptr_t) ecKeyId);
  ICC_EVP_PKEY * ockPKey = NULL;
  jlong          pkeyId = 0;
  int            rc = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  ockPKey = ICC_EVP_PKEY_new(ockCtx);
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC ockPKey=%lx", (long) ockPKey);
  }
#endif
  if( ockPKey == NULL ) {
    ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE ICC_EVP_PKEY_new");
    }
#endif
    throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
  } 
  else 
  {
    rc = ICC_EVP_PKEY_set1_EC_KEY(ockCtx, ockPKey, ockECKey);
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC ICC_EVP_PKEY_set1_EC_KEY returned %d", rc);
    }
#endif
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE ICC_EVP_PKEY_set1_EC_KEY rc=%d", rc);
      }
#endif
      throwOCKException(env, 0, "ICC_EVP_PKEY_set1_EC_KEY failed");
    } 
    else 
    {
      pkeyId = (jlong)((intptr_t)ockPKey);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) {
        gslogMessage ("DETAIL_EC pkeyId=%lx", pkeyId);
      }
#endif
    }
  }

  if( (ockPKey != NULL) && (pkeyId == 0) ) {
    ICC_EVP_PKEY_free(ockCtx, ockPKey);
    ockPKey = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return pkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1delete
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ecKeyId)
{
  static const char * functionName = "NativeInterface.ECKEY_delete";

  ICC_CTX *    ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY * ockECKey = (ICC_EC_KEY *)((intptr_t) ecKeyId);

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage("DETAIL_EC ecKeyId=%lx", ecKeyId);
  }
#endif
  if (ockECKey != NULL) {
    ICC_EC_KEY_free(ockCtx, ockECKey);
    ockECKey = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1delete
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong xecKeyId)
{
  static const char * functionName = "NativeInterface.XECKEY_delete";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY *  ockEVPKey = (ICC_EVP_PKEY *)((intptr_t)xecKeyId);

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage("DETAIL_EC ecKeyId=%lx", xecKeyId);
  }
#endif
  if (ockEVPKey != NULL) {
    ICC_EVP_PKEY_free(ockCtx, ockEVPKey);
    ockEVPKey = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
}


//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_computeECDHSecret
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1computeECDHSecret
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong pubEcKeyId, jlong privEcKeyId)
{
  static const char * functionName = "NativeInterface_ECKEY_1computeECDHSecret";
  
  ICC_CTX *            ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *         ockPubEcKey = (ICC_EC_KEY *)((intptr_t) pubEcKeyId);
  const ICC_EC_KEY *   ockPrivEcKey = (const ICC_EC_KEY *)((intptr_t) privEcKeyId);
  const ICC_EC_POINT * ockEcPoint;
  const ICC_EC_GROUP * ockEcGroup;
  jbyteArray           secretBytes = NULL;
  unsigned char *      secretBytesNative = NULL;
  jboolean             isCopy = 0;
  jbyteArray           retSecretBytes = NULL;
  int                  size = 32; //by default
  int                  lena = 0;
  int                  groupDegree;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

#ifdef DEBUG_EC_DETAIL
  if ( debug ) {
    gslogMessage ("DETAIL_EC PubEcKeyId=%d", pubEcKeyId);
  }
#endif
  ockEcPoint = ICC_EC_KEY_get0_public_key (ockCtx,  ockPubEcKey);
#ifdef DEBUG_EC_DETAIL
  if ( debug ) {
    gslogMessage ("DETAIL_EC ockEcPoint=%d", (long) ockEcPoint);
  }
#endif
  if (ockEcPoint == NULL) {
    /* fprintf (stderr, "ockEcPoint is null; ICC_EC_KEY_get0_public_key failed\n");*/
    ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE ICC_EC_KEY_get0_public_key");
    }
#endif
    throwOCKException(env, 0, "ICC_EC_KEY_get0_public_key failed");
  }
  else
  {
    ockEcGroup = ICC_EC_KEY_get0_group (ockCtx, (const ICC_EC_KEY *) ockPrivEcKey);
    if (ockEcGroup == NULL) {
        size = 32;
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC size hard coded to 32");
    }
#endif
    }
    else
    {
        groupDegree = ICC_EC_GROUP_get_degree(ockCtx, ockEcGroup);
        size = (groupDegree + 7)/8;
    }
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC size calculated from curve=%d", size);
    }
#endif
    secretBytes = (*env)->NewByteArray(env, size);
    if( secretBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
      if (debug) {
        gslogMessage("DETAIL_EC FAILURE secretBytes");
      }
#endif
      throwOCKException(env, 0, "NewByteArray failed");
    }
    else
    {
      secretBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, secretBytes, &isCopy));
#ifdef DEBUG_EC_DETAIL
      if ( debug ) {
        gslogMessage ("DETAIL_EC secretBytesNative allocated");
      }
#endif
      if( secretBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE secretBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      }
      else
      {
        unsigned char * pBytes = (unsigned char *)secretBytesNative;
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC ockEcPoint=%ld ockPrivEcKey %x", (long) ockEcPoint, ockPrivEcKey);
        }
#endif

        lena = ICC_ECDH_compute_key (ockCtx, pBytes, size, ockEcPoint, (ICC_EC_KEY *) ockPrivEcKey, NULL);
#ifdef DEBUG_EC_DETAIL
      if ( debug ) {
        gslogMessage ("DETAIL_EC lena=%d", lena);
      }
#endif
        if (lena == -(ICC_ERROR_FLAG)) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
          if (debug) {
            gslogMessage("DETAIL_EC FAILURE lena ICC_ECDH_compute_key %d", lena);
          }
#endif
          throwOCKException(env, 0, "ICC_EC_KEY_get0_public_key failed");
        }
        else
        {
#ifdef DEBUG_EC_DATA
          if ( debug ) { 
            gslogMessagePrefix ("DATA_EC computed secretBytes : ");
            gslogMessageHex ((char *)  pBytes, 0, lena, 0, 0, NULL);
          }
#endif
          retSecretBytes = secretBytes;
          if( secretBytesNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, secretBytes, secretBytesNative, 0);
          }

          if((secretBytes != NULL) && (retSecretBytes == NULL)) {
            (*env)->DeleteLocalRef(env, secretBytes);
          }

          if( debug ) {
            gslogFunctionExit(functionName);
          }
          return retSecretBytes;
        }
      }        
    }       
  }

  if( secretBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, secretBytes, secretBytesNative, 0);
  }

  if((secretBytes != NULL) && (retSecretBytes == NULL)) {
    (*env)->DeleteLocalRef(env, secretBytes);
  }
#ifdef DEBUG_EC_DETAIL
  if ( debug ) {
    gslogMessage ("DETAIL_EC returning NULL");
  }
#endif

  if( debug ) {
    gslogFunctionExit(functionName);
  }
  return NULL;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    XECKEY_computeECDHSecret
 * Signature: (JJJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_XECKEY_1computeECDHSecret
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong genCtx, jlong pubXecKeyId, jlong privXecKeyId, jint secretBufferSize)
{
  static const char * functionName = "NativeInterface_XECKEY_1computeECDHSecret";

  ICC_CTX *            ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
  ICC_EVP_PKEY *       ockPubXecKey = (ICC_EVP_PKEY *)((intptr_t)pubXecKeyId);
  const ICC_EVP_PKEY * ockPrivXecKey = (const ICC_EVP_PKEY *)((intptr_t)privXecKeyId);
  ICC_EVP_PKEY_CTX *   gen_ctx = NULL;
  jbyteArray           secretBytes = NULL;
  unsigned char *      secretBytesNative = NULL;
  jboolean             isCopy = 0;
  jbyteArray           retSecretBytes = NULL;
  size_t               secret_key_len = 0;

  
  if( debug ) gslogFunctionEntry(functionName);

  gen_ctx = ICC_EVP_PKEY_CTX_new(ockCtx,(ICC_EVP_PKEY *) ockPrivXecKey,NULL); /* Set private key */
  if(gen_ctx == NULL) throwOCKException(env, 0, "NULL from ICC_EVP_PKEY_CTX_new"); 
  else {
    ICC_EVP_PKEY_derive_init(ockCtx, gen_ctx);
    ICC_EVP_PKEY_derive_set_peer(ockCtx, gen_ctx, ockPubXecKey); /* Set public key */
    if (secretBufferSize > 0) {
        secret_key_len = secretBufferSize;
    } else {
        ICC_EVP_PKEY_derive(ockCtx, gen_ctx, NULL, &secret_key_len); /* Get secret key size */
    }
    secretBytes = (*env)->NewByteArray(env, secret_key_len); /* Create Java secret bytes array with size */
    if( secretBytes == NULL ) throwOCKException(env, 0, "NewByteArray failed"); 
    else {
      secretBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, secretBytes, &isCopy));
      if( secretBytesNative == NULL ) throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical"); 
      else {
        ICC_EVP_PKEY_derive(ockCtx, gen_ctx, secretBytesNative, &secret_key_len);
        retSecretBytes = secretBytes;
        if( secretBytesNative != NULL ) (*env)->ReleasePrimitiveArrayCritical(env, secretBytes, secretBytesNative, 0);
        if((secretBytes != NULL) && (retSecretBytes == NULL)) (*env)->DeleteLocalRef(env, secretBytes);
        if( debug ) gslogFunctionExit(functionName);
        return retSecretBytes;
      }
    }
    if (gen_ctx != NULL) {
      ICC_EVP_PKEY_CTX_free(ockCtx,gen_ctx);
      gen_ctx = NULL;
    }
  }

  if( secretBytesNative != NULL ) (*env)->ReleasePrimitiveArrayCritical(env, secretBytes, secretBytesNative, 0);
  if((secretBytes != NULL) && (retSecretBytes == NULL)) (*env)->DeleteLocalRef(env, secretBytes);
  if( debug ) gslogFunctionExit(functionName);
  return NULL;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_signDatawithECDSA
 * Signature: (J[BIJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1signDatawithECDSA
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray digestBytes, jint digestBytesLen, jlong privEcKeyId)
{
  static const char * functionName = "NativeInterface_ECKEY_1signDatawithECDSA";
  
  
  ICC_CTX *             ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *          ockPrivEcKey = (ICC_EC_KEY *)((intptr_t) privEcKeyId);
  unsigned char *       digestBytesNative = NULL;
  jbyteArray            sigBytes = NULL;
  unsigned char *       sigBytesNative = NULL;
  jboolean              isCopy = 0;
  jbyteArray            retSigBytes = NULL;
  int                   retSigBytesLen = 0;
  int                   type = 0;
  const unsigned char * pBytesDigest = NULL;
  unsigned char *       pBytesSig = NULL;
  jint                  size = 0;
  int                   rc = 0;
  
  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  
#ifdef DEBUG_EC_DETAIL
  if( debug ) {
    gslogMessage ("DETAIL_EC privEcKeyId=%lx, digestBytesLen=%d", privEcKeyId, (int) digestBytesLen);
  }
#endif
  
  digestBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, digestBytes, &isCopy));
  if( digestBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE digestBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } 
  else 
  {
#ifdef DEBUG_EC_DETAIL
    if( debug ) {
      gslogMessage ("DETAIL_EC Allocated digestBytesNative");
    }
#endif
    pBytesDigest = digestBytesNative;

    size = (*env)->GetArrayLength(env, digestBytes);
    /*fprintf (stderr, "size=%d\n", size);*/
#ifdef DEBUG_EC_DETAIL
    if( debug ) {
      gslogMessage ("DETAIL_EC size=%d", size);
    }
#endif
    if( size != digestBytesLen )
    {

#ifdef DEBUG_EC_DETAIL
    if( debug ) {
      gslogMessage ("DETAIL_EC FAILURE Internal inconsistency while validating the digest length parameter %d %d", (int) size, (int) digestBytesLen);
    }
#endif
      throwOCKException(env, 0, "Internal inconsistency while validating the digest length parameter");
    }
    else
    {
      /* calculate how much to allocated for signed bytes */
      int maxSigBytesLen = ICC_ECDSA_size (ockCtx,  ockPrivEcKey);
#ifdef DEBUG_EC_DETAIL
    if( debug ) {
      gslogMessage ("DETAIL_EC maxSigBytesLen=%d", maxSigBytesLen);
    }
#endif
      sigBytes = (*env)->NewByteArray(env, maxSigBytesLen);
      if( sigBytes == NULL ) {
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE sigBytes");
        }
#endif
        throwOCKException(env, 0, "NewByteArray(sigBytes) failed");
      } 
      else 
      {
        sigBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
        pBytesSig = (unsigned char *)sigBytesNative;
        if( sigBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE sigBytesNative");
        }
#endif
          throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical for sigBytes");
        } 
        else
        {
        
          pBytesSig = (unsigned char *)sigBytesNative;
          rc = ICC_ECDSA_sign (ockCtx, type, pBytesDigest, size, pBytesSig, (unsigned int *) &retSigBytesLen, ockPrivEcKey);
#ifdef DEBUG_EC_DATA
          if ( debug ) {
            gslogMessage ("DATA_EC ICC_ECDSA_sign rc=%d", rc);
            gslogMessagePrefix ("DATA_EC sigBytes length =%d", retSigBytesLen);
            gslogMessageHex ((char *)  pBytesSig, 0, (int) retSigBytesLen, 0, 0, NULL);
          }
#endif
          if ( rc != 1 )
          {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_EC_DETAIL
            if (debug) {
              gslogMessage("DETAIL_EC FAILURE ICC_ECDSA_sign rc %d", rc);
             }
#endif
            throwOCKException(env, 0, "Failed to sign");
          }
          else
          {
#ifdef DEBUG_EC_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_EC ICC_ECDSA_sign rc=%d", rc);
          }
#endif
            /*if(retSigBytesLen != maxSigBytesLen) {
              gslogError ("retSigBytesLen %d maxSigBytesLen %d\n", retSigBytesLen, maxSigBytesLen);
            }
            */
            
            retSigBytes = sigBytes;
            
            if( digestBytesNative != NULL ) {
              (*env)->ReleasePrimitiveArrayCritical(env, digestBytes, digestBytesNative, 0);
            }
            if( sigBytesNative != NULL ) {
              (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
            }

            if((sigBytes != NULL) && (retSigBytes == NULL)) {
              (*env)->DeleteLocalRef(env, sigBytes);
            }

            if( debug ) {
              gslogFunctionExit(functionName);
            }
            return retSigBytes;           
          }
        }
      }  
    }

  }
   
  if( digestBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, digestBytes, digestBytesNative, 0);
  }
  if( sigBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
  }

  if((sigBytes != NULL) && (retSigBytes == NULL)) {
    (*env)->DeleteLocalRef(env, sigBytes);
  } 
    
  if( debug ) {
    gslogFunctionExit(functionName);
  }
  return NULL;
}
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    ECKEY_verifyDatawithECDSA
 * Signature: (J[BI[BIJ)Z
 */
JNIEXPORT jboolean JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_ECKEY_1verifyDatawithECDSA
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray digestBytes, jint digestBytesLen, jbyteArray sigBytes, jint sigBytesLen, jlong pubEcKeyId) 
  
{  
  static const char * functionName = "NativeInterface_ECKEY_1verifyDatawithECDSA";
  
  ICC_CTX *             ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EC_KEY *          ockPubEcKey = ( ICC_EC_KEY *)((intptr_t) pubEcKeyId);
  unsigned char *       digestBytesNative = NULL;
  unsigned char *       sigBytesNative = NULL;
  jboolean              isCopy = 0;
  int                   verified = 0;
  int                   type = 0;
  const unsigned char * pBytesDigest = NULL;
  const unsigned char * pBytesSig  = NULL;
  jint                  size = 0;
  
  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  
  digestBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, digestBytes, &isCopy));
  if( digestBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
    if (debug) {
      gslogMessage("DETAIL_EC FAILURE digestBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } 
  else 
  {
    pBytesDigest = (const unsigned char *)digestBytesNative;
    size = (*env)->GetArrayLength(env, digestBytes);
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC size=%d digestBytesLen %d", size, (int) digestBytesLen); 
    }
#endif
    if (size != digestBytesLen)
    {
#ifdef DEBUG_EC_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_EC FAILURE Internal Inconsistency while validating the digest length parameter");
    }
#endif
      throwOCKException(env, 0, "Internal inconsistency while validating the digest length parameter");
    }
    else
    {
    
      sigBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
      if( sigBytesNative == NULL ) {
#ifdef DEBUG_EC_DETAIL
        if (debug) {
          gslogMessage("DETAIL_EC FAILURE sigBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
      } 
      else 
      {
        
        pBytesSig = (unsigned char *)sigBytesNative;
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessagePrefix ("DETAIL_EC Signature Bytes : "); 
          gslogMessageHex ((char *)  pBytesSig, 0, size, 0, 0, NULL); 
        }
#endif
        
        verified = ICC_ECDSA_verify (ockCtx, type, pBytesDigest, size, pBytesSig, sigBytesLen, ockPubEcKey);
#ifdef DEBUG_EC_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_EC verified=%d", verified); 
        }
#endif
        if (verified != 1)
        {
          ockCheckStatus(ockCtx);
          /* throwOCKException(env, 0, "Failed to verify");*/
        }
        else
        {
          if( digestBytesNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, digestBytes, digestBytesNative, 0);
          }
          if( sigBytesNative != NULL ) {
            (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
          }

          if( debug ) {
            gslogFunctionExit(functionName);
          }
          return (verified == 1);           
        }
      }  
    }
  }
    
    
  if( debug ) {
    gslogFunctionExit(functionName);
  }
  

  return (verified == 1);
  
}
