###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = $(BUILDTOP)\host64
NATIVE_DIR = $(NATIVE_TOPDIR)\ock
NATIVE_LIB_HOME = $(GSKIT_HOME)
JNI_CLASS = $(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\NativeOCKImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_ock_NativeOCKImplementation.h

OBJS= \
	AESKeyWrap.obj \
	BasicRandom.obj \
	BuildDate.obj \
	CCM.obj \
	Digest.obj \
	DHKey.obj \
	DSAKey.obj \
	ECKey.obj \
	ExtendedRandom.obj \
	GCM.obj \
	HKDF.obj \
	HMAC.obj \
	KEM.obj \
	MLKey.obj \
	PBKDF.obj \
	PKey.obj \
	Poly1305Cipher.obj \
	RSA.obj \
	RSAKey.obj \
	RsaPss.obj \
	Signature.obj \
	SignatureDSANONE.obj \
	SignatureEdDSA.obj \
	SignaturePQC.obj \
	SignatureRSASSL.obj \
	StaticStub.obj \
	SymmetricCipher.obj \
	Utils.obj

TARGET = libjgskit_64.dll

RC_SRC = jgskit_resource.rc
RC_OBJ = jgskit_resource.res

TARGET_LIBS = -LIBPATH:"$(NATIVE_LIB_HOME)\lib" jgsk8iccs_64.lib

!INCLUDE ../share/common.win64.cygwin.mak

