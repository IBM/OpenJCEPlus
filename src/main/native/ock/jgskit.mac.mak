###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = ${BUILDTOP}/jgskit-${PLATFORM}
NATIVE_DIR = ${NATIVE_TOPDIR}/ock
NATIVE_LIB_HOME = ${GSKIT_HOME}
JNI_CLASS = ${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_ock_NativeOCKImplementation.h
TARGET_LIBS := -L ${GSKIT_HOME}/lib64 -l jgsk8iccs

OBJS = \
	${HOSTOUT}/AESKeyWrap.o \
	${HOSTOUT}/BasicRandom.o \
	${HOSTOUT}/BuildDate.o \
	${HOSTOUT}/CCM.o \
	${HOSTOUT}/Digest.o \
	${HOSTOUT}/DHKey.o \
	${HOSTOUT}/DSAKey.o \
	${HOSTOUT}/ECKey.o \
	${HOSTOUT}/ExtendedRandom.o \
	${HOSTOUT}/GCM.o \
	${HOSTOUT}/HKDF.o \
	${HOSTOUT}/HMAC.o \
	${HOSTOUT}/KEM.o \
	${HOSTOUT}/MLKey.o \
	${HOSTOUT}/PBKDF.o \
	${HOSTOUT}/PKey.o \
	${HOSTOUT}/Poly1305Cipher.o \
	${HOSTOUT}/RSA.o \
	${HOSTOUT}/RSAKey.o \
	${HOSTOUT}/RsaPss.o \
	${HOSTOUT}/Signature.o \
	${HOSTOUT}/SignatureDSANONE.o \
	${HOSTOUT}/SignatureEdDSA.o \
	${HOSTOUT}/SignaturePQC.o \
	${HOSTOUT}/SignatureRSASSL.o \
	${HOSTOUT}/StaticStub.o \
	${HOSTOUT}/SymmetricCipher.o \
	${HOSTOUT}/Utils.o

TARGET = ${HOSTOUT}/libjgskit.dylib

include ../share/common.mac.mak
