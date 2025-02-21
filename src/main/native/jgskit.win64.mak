###############################################################################
#
# Copyright IBM Corp. 2023, 2025
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR = $(MAKEDIR)../../..

PLAT = win
CFLAGS= -nologo -DWINDOWS

#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_PBKDF_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system,  enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA
#DEBUG_FLAGS = -DDEBUG $(DEBUG_DETAIL)  $(DEBUG_DATA)

BUILDTOP = $(TOPDIR)/target/build$(PLAT)
HOSTOUT = $(BUILDTOP)/host64
OPENJCEPLUS_HEADER_FILES ?= $(TOPDIR)/src/main/native
JAVACLASSDIR = $(TOPDIR)/target/classes

OBJS= \
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
	$(HOSTOUT)/PBKDF.obj \
	$(HOSTOUT)/PKey.obj \
	$(HOSTOUT)/Poly1305Cipher.obj \
	$(HOSTOUT)/RSA.obj \
	$(HOSTOUT)/RSAKey.obj \
	$(HOSTOUT)/RsaPss.obj \
	$(HOSTOUT)/Signature.obj \
	$(HOSTOUT)/SignatureDSANONE.obj \
	$(HOSTOUT)/SignatureRSASSL.obj \
	$(HOSTOUT)/StaticStub.obj \
	$(HOSTOUT)/SymmetricCipher.obj \
	$(HOSTOUT)/Utils.obj

TARGET = $(HOSTOUT)/libjgskit_64.dll

JGSKIT_RC_SRC = jgskit_resource.rc
JGSKIT_RC_OBJ = $(HOSTOUT)/jgskit_resource.res

all : $(TARGET)

$(TARGET) : $(OBJS) $(JGSKIT_RC_OBJ)
	link -dll -out:$@ $(OBJS) $(JGSKIT_RC_OBJ) -LIBPATH:"$(GSKIT_HOME)/lib" jgsk8iccs_64.lib

$(JGSKIT_RC_OBJ) : $(JGSKIT_RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(JGSKIT_RC_SRC)

$(HOSTOUT)/%.obj : %.c
	-@mkdir -p $(HOSTOUT) 2>nul
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(GSKIT_HOME)/inc" \
		-I"$(JAVA_HOME)/include" \
		-I"$(JAVA_HOME)/include/win32" \
		-I"$(OPENJCEPLUS_HEADER_FILES)" \
		-Fo$@ \
		$<

# Force BuildDate to be recompiled every time
#
$(HOSTOUT)/BuildDate.obj : FORCE

FORCE :

ifneq (${EXTERNAL_HEADERS},true)

$(OBJS) : | headers

headers :
	echo "Compiling OpenJCEPlus headers"
	$(JAVA_HOME)/bin/javac \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d $(JAVACLASSDIR) \
		-h $(TOPDIR)/src/main/native/ \
		$(TOPDIR)/src/main/java/com/ibm/crypto/plus/provider/ock/FastJNIBuffer.java \
		$(TOPDIR)/src/main/java/com/ibm/crypto/plus/provider/ock/NativeInterface.java

endif # ! EXTERNAL_HEADERS

clean :
	-@del $(HOSTOUT)/*.obj
	-@del $(HOSTOUT)/*.exp
	-@del $(HOSTOUT)/*.lib
	-@del $(HOSTOUT)/*.dll
	-@del $(HOSTOUT)/*.res

