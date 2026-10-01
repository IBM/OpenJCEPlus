###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = $(BUILDTOP)\ojp-host64
NATIVE_DIR = $(NATIVE_TOPDIR)\openssl
NATIVE_LIB_HOME = $(OPENSSL_HOME)
JNI_CLASS = $(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\openssl\NativeOpenSSLImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h

OBJS= \
	OpenSSLNativeInterface.obj \
	OpenSSLSymmetricCipher.obj \
	OpenSSLGCM.obj \
	OpenSSLCCM.obj \
	OpenSSLKeyWrap.obj \
	OpenSSLRandom.obj \
	OpenSSLUtils.obj \
	OpenSSLHelpers.obj \
	Digest.obj \
	BuildDate.obj

TARGET = libopenjceplus_64.dll

RC_SRC = openjceplus_resource.rc
RC_OBJ = openjceplus_resource.res

TARGET_LIBS = -LIBPATH:"$(NATIVE_LIB_HOME)\lib" libcrypto.lib libssl.lib ws2_32.lib crypt32.lib advapi32.lib user32.lib

# Pull in common rules first so that `all` is the default nmake target.
# The OpenSSLNativeInterface.obj special rule (source name differs from object
# name) must follow the !INCLUDE so it overrides the generic .c.obj pattern
# without displacing `all` as the default target.
!INCLUDE ../share/common.win64.cygwin.mak

# OpenSSLJNI.c compiles to OpenSSLNativeInterface.obj (source filename differs from object name).
OpenSSLNativeInterface.obj : OpenSSLJNI.c OpenSSLHelpers.h
	$(CC) $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(NATIVE_LIB_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I. OpenSSLJNI.c -Fo$@
