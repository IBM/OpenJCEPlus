###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = $(BUILDTOP)/ojp-host64
NATIVE_DIR = $(NATIVE_TOPDIR)/openssl
NATIVE_LIB_HOME = $(OPENSSL_HOME)
JNI_CLASS = $(TOPDIR)/src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h

OBJS= \
	$(HOSTOUT)/BuildDate.obj \
	$(HOSTOUT)/Digest.obj \
	$(HOSTOUT)/StaticStub.obj \
	$(HOSTOUT)/Utils.obj

ifndef OPENSSL_LIB_LOCATION
	OPENSSL_LIB_LOCATION = ${OPENSSL_HOME}/lib
endif

ifndef OPENSSL_LIB
	OPENSSL_LIB = crypto
endif

TARGET = $(HOSTOUT)/libopenjceplus_64.dll

RC_SRC = openjceplus_resource.rc
RC_OBJ = $(HOSTOUT)/openjceplus_resource.res

TARGET_LIBS = -LIBPATH:"$(OPENSSL_LIB_LOCATION)" lib$(OPENSSL_LIB).lib

include ../share/common.win64.mak
