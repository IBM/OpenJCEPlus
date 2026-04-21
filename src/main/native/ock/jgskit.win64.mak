###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = $(BUILDTOP)/host64
NATIVE_DIR = $(NATIVE_TOPDIR)/ock
NATIVE_LIB_HOME = $(GSKIT_HOME)
JNI_CLASS = $(TOPDIR)/src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_ock_NativeOCKImplementation.h

OBJS= \
	$(HOSTOUT)/AESKeyWrap.obj \
	$(HOSTOUT)/BasicRandom.obj \
	$(HOSTOUT)/BuildDate.obj \
	$(HOSTOUT)/CCM.obj \
	$(HOSTOUT)/Digest.obj \
	$(HOSTOUT)/DHKey.obj \
	$(HOSTOUT)/DSAKey.obj \
	$(HOSTOUT)/ECKey.obj \
	$(HOSTOUT)/ExtendedRandom.obj \
	$(HOSTOUT)/GCM.obj \
	$(HOSTOUT)/HKDF.obj \
	$(HOSTOUT)/HMAC.obj \
	$(HOSTOUT)/KEM.obj \
	$(HOSTOUT)/MLKey.obj \
	$(HOSTOUT)/PBKDF.obj \
	$(HOSTOUT)/PKey.obj \
	$(HOSTOUT)/Poly1305Cipher.obj \
	$(HOSTOUT)/RSA.obj \
	$(HOSTOUT)/RSAKey.obj \
	$(HOSTOUT)/RsaPss.obj \
	$(HOSTOUT)/Signature.obj \
	$(HOSTOUT)/SignatureDSANONE.obj \
	$(HOSTOUT)/SignatureEdDSA.obj \
	$(HOSTOUT)/SignaturePQC.obj \
	$(HOSTOUT)/SignatureRSASSL.obj \
	$(HOSTOUT)/StaticStub.obj \
	$(HOSTOUT)/SymmetricCipher.obj \
	$(HOSTOUT)/Utils.obj

TARGET = $(HOSTOUT)/libjgskit_64.dll

RC_SRC = jgskit_resource.rc
RC_OBJ = $(HOSTOUT)/jgskit_resource.res

TARGET_LIBS = -LIBPATH:"$(NATIVE_LIB_HOME)/lib" jgsk8iccs_64.lib

include ../share/common.win64.mak
