###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR       = $(MAKEDIR)\..\..\..\..
PLAT         = opensslwin
CFLAGS       = -nologo -DWINDOWS -MD
CC           = cl

#DEBUG_DETAIL = -DDEBUG_OPENSSL_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_CIPHER_DETAIL
#DEBUG_DATA   = -DDEBUG_OPENSSL_DATA   -DDEBUG_DIGEST_DATA   -DDEBUG_CIPHER_DATA
#DEBUG_FLAGS  = -DDEBUG $(DEBUG_DETAIL) $(DEBUG_DATA)

BUILDTOP     = $(TOPDIR)\target\build$(PLAT)
HOSTOUT      = $(BUILDTOP)\host64
JAVACLASSDIR = $(TOPDIR)\target\classes
NATIVE_DIR   = $(MAKEDIR)
JNI_CLASS    = $(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\openssl\NativeOpenSSLImplementation.java

OBJS = \
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

TARGET_LIBS = -LIBPATH:"$(OPENSSL_HOME)\lib" libcrypto.lib libssl.lib ws2_32.lib crypt32.lib advapi32.lib user32.lib

all : displaycompiler headers $(TARGET) copy

$(TARGET) : $(OBJS) $(RC_OBJ)
	link -dll -out:$@ $(OBJS) $(RC_OBJ) $(TARGET_LIBS)

$(RC_OBJ) : $(RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(RC_SRC)

.c.obj :
	$(CC) \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I. \
		$*.c

# OpenSSLJNI.c compiles to OpenSSLNativeInterface.obj (source filename differs from object name).
OpenSSLNativeInterface.obj : OpenSSLJNI.c OpenSSLHelpers.h
	$(CC) $(DEBUG_FLAGS) $(CFLAGS) -c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I. \
		OpenSSLJNI.c -Fo$@

# Force BuildDate to be recompiled every time so the build timestamp is current.
BuildDate.obj : FORCE

FORCE :

headers :
	@echo "Compiling OpenJCEPlus headers"
	"$(JAVA_HOME)\bin\javac" \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d $(JAVACLASSDIR) \
		-h $(NATIVE_DIR)\ \
		$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\base\FastJNIBuffer.java \
		$(JNI_CLASS)

displaycompiler :
	@echo "Compiler version: " && $(CC)
	@echo "Building with $(CC) compiler..."
	@echo "-------------------------------------"

copy : $(TARGET)
	-@if not exist "$(HOSTOUT)" mkdir "$(HOSTOUT)"
	-copy /Y *.obj "$(HOSTOUT)" >nul 2>&1
	-copy /Y $(RC_OBJ) "$(HOSTOUT)" >nul 2>&1
	-copy /Y $(TARGET) "$(HOSTOUT)" >nul 2>&1

clean :
	-del /Q *.obj *.exp *.lib *.dll *.res 2>nul

.PHONY : all clean copy displaycompiler headers
