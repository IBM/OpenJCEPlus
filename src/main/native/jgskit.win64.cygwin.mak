###############################################################################
#
# Copyright IBM Corp. 2023, 2025
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR = $(MAKEDIR)\..\..\..

PLAT = win
CFLAGS= -nologo -DWINDOWS

#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL -DDEBUG_PBKDF_DETAIL -DDEBUG_PQC_KEY_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system,  enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS = -DDEBUG $(DEBUG_DETAIL)  $(DEBUG_DATA)

BUILDTOP = $(TOPDIR)\target\build$(PLAT)
HOSTOUT = $(BUILDTOP)\host64
JAVACLASSDIR = $(TOPDIR)\target\classes

OBJS= \
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

JGSKIT_RC_SRC = jgskit_resource.rc
JGSKIT_RC_OBJ = jgskit_resource.res

all : copy

copy : $(TARGET)
	-@mkdir -p $(HOSTOUT) 2>nul
	-@cp *.obj $(HOSTOUT)
	-@cp jgskit_resource.res $(HOSTOUT)
	-@cp libjgskit_64.dll $(HOSTOUT)

$(TARGET) : $(OBJS) $(JGSKIT_RC_OBJ)
	link -dll -out:$@ $(OBJS) $(JGSKIT_RC_OBJ) -LIBPATH:"$(GSKIT_HOME)/lib" jgsk8iccs_64.lib

$(JGSKIT_RC_OBJ) : $(JGSKIT_RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(JGSKIT_RC_SRC)

.c.obj :
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(GSKIT_HOME)/inc" \
		-I"$(JAVA_HOME)/include" \
		-I"$(JAVA_HOME)/include/win32" \
		$*.c

# Force BuildDate to be recompiled every time
#
BuildDate.obj : FORCE

FORCE :

$(OBJS) : headers

headers :
	echo "Compiling OpenJCEPlus headers"
	$(JAVA_HOME)\bin\javac \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d $(JAVACLASSDIR) \
		-h $(TOPDIR)\src\main\native\ \
		$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\FastJNIBuffer.java \
		$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\NativeInterface.java

clean :
	-@del $(HOSTOUT)\*.obj
	-@del $(HOSTOUT)\*.exp
	-@del $(HOSTOUT)\*.lib
	-@del $(HOSTOUT)\*.dll
	-@del $(HOSTOUT)\*.res

.PHONY : all clean copy headers
