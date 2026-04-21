###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR = $(MAKEDIR)../../../..

PLAT = win
CFLAGS= -nologo -DWINDOWS
CC = cl

#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL -DDEBUG_PBKDF_DETAIL -DDEBUG_PQC_KEY_DETAIL

#Setting this flag will result in sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the user that it not suitable to deploy this native library on a production system, while enabling this flag.
#This flag must be disabled before building production version.
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS = -DDEBUG $(DEBUG_DETAIL)  $(DEBUG_DATA)

BUILDTOP = $(TOPDIR)/target/build$(PLAT)
NATIVE_TOPDIR = $(TOPDIR)/src/main/native
OPENJCEPLUS_HEADER_FILES ?= $(NATIVE_DIR)
JAVACLASSDIR = $(TOPDIR)/target/classes

all : displaycompiler $(TARGET)

$(TARGET) : $(OBJS) $(RC_OBJ)
	link -dll -out:$@ $(OBJS) $(RC_OBJ) $(TARGET_LIBS)

$(RC_OBJ) : $(RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(RC_SRC)

$(HOSTOUT)/%.obj : %.c
	-@mkdir -p $(HOSTOUT) 2>nul
	$(CC) \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(NATIVE_LIB_HOME)/inc" \
		-I"$(JAVA_HOME)/include" \
		-I"$(JAVA_HOME)/include/win32" \
		-I"$(OPENJCEPLUS_HEADER_FILES)" \
		-Fo$@ \
		$<

displaycompiler :
	@echo "Compiler version: " && $(CC)
	@echo "Building with $(CC) compiler..."
	@echo "-------------------------------------"

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
		-h $(TOPDIR)/src/main/native/ock/ \
		$(TOPDIR)/src/main/java/com/ibm/crypto/plus/provider/base/FastJNIBuffer.java \
		$(JNI_CLASS)

endif # ! EXTERNAL_HEADERS

clean :
	-@del $(HOSTOUT)/*.obj
	-@del $(HOSTOUT)/*.exp
	-@del $(HOSTOUT)/*.lib
	-@del $(HOSTOUT)/*.dll
	-@del $(HOSTOUT)/*.res

