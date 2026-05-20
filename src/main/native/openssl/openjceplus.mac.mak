###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = ${BUILDTOP}/ojp-${PLATFORM}
NATIVE_DIR = ${NATIVE_TOPDIR}/openssl
NATIVE_LIB_HOME = ${OPENSSL_HOME}
JNI_CLASS = ${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h

ifndef OPENSSL_LIB_LOCATION
	OPENSSL_LIB_LOCATION = ${JAVA_HOME}/lib
	OPENSSL_LIB = crypto-semeru
else
	OPENSSL_LIB = crypto
endif

TARGET_LIBS := -L ${OPENSSL_LIB_LOCATION} -l ${OPENSSL_LIB}

OBJS = \
	${HOSTOUT}/Digest.o \
	${HOSTOUT}/Utils.o

TARGET = ${HOSTOUT}/libopenjceplus.dylib

include ../share/common.mac.mak
