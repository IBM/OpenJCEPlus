###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = ${BUILDTOP}/ojp-${PLAT}-64
NATIVE_DIR = ${NATIVE_TOPDIR}/openssl
NATIVE_LIB_HOME = ${OPENSSL_HOME}
JNI_CLASS = ${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h

OBJS = \
	${HOSTOUT}/BuildDate.o \
	${HOSTOUT}/Digest.o \
	${HOSTOUT}/StaticStub.o \
	${HOSTOUT}/Utils.o

LIB_FOLDER = lib
ifeq (${PLATFORM},x86-linux64)
	LIB_FOLDER = lib64
endif

ifndef OPENSSL_LIB_LOCATION
	OPENSSL_LIB_LOCATION = ${OPENSSL_HOME}/${LIB_FOLDER}
endif

ifndef OPENSSL_LIB
	OPENSSL_LIB = crypto
endif

ifndef OPENSSL_LIB_VERSION
	OPENSSL_LIB_VERSION = 3
endif

TARGET = ${HOSTOUT}/libopenjceplus.so
ifeq (${PLATFORM},ppc-aix64)
	TARGET_LIBS := ${OPENSSL_LIB_LOCATION}/libcrypto64.so.${OPENSSL_LIB_VERSION}
else
	TARGET_LIBS := -L ${OPENSSL_LIB_LOCATION} -l ${OPENSSL_LIB}
endif

include ../share/common.mak
