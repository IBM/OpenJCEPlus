###############################################################################
#
# Copyright IBM Corp. 2023
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#
###############################################################################

TOPDIR = $(MAKEDIR)\..\..\..

PLAT = win
BUILDTOP = $(TOPDIR)\target\build$(PLAT)
HOSTOUT = $(BUILDTOP)\host64
JAVACLASSDIR = $(TOPDIR)\target\classes
#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system,  enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS = -DDEBUG $(DEBUG_DETAIL)  $(DEBUG_DATA)

OBJS= BasicRandom.obj \
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
      PKey.obj \
      Poly1305Cipher.obj \
      RSA.obj \
      RSAKey.obj \
      RsaPss.obj \
      Signature.obj \
      SignatureDSANONE.obj \
      SignatureRSASSL.obj \
      StaticStub.obj \
      SymmetricCipher.obj \
      Utils.obj \
      SignatureEdDSA.obj

JGSKIT_RC_SRC = jgskit_resource.rc
JGSKIT_RC_OBJ = jgskit_resource.res


TARGET = libjgskit_64.dll

all:  dircreate javah $(TARGET) copy

dircreate:
	-@mkdir -p $(HOSTOUT) 2>nul

javah: dircreate
	$(JAVA_HOME)\bin\javac --add-exports java.base/jdk.internal.misc=ALL-UNNAMED \
	$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\NativeInterface.java \
	$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\FastJNIBuffer.java \
	$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\OCKContext.java \
	$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\ock\OCKException.java \
	-d $(JAVACLASSDIR) -h $(TOPDIR)\src\main\native\

$(TARGET): $(OBJS) $(JGSKIT_RC_OBJ)
	-link -dll -out:$@ $(OBJS) $(JGSKIT_RC_OBJ) -LIBPATH:"$(GSKIT_HOME)/lib" jgsk8iccs_64.lib

copy:
    -@cp *.obj $(HOSTOUT)
    -@cp jgskit_resource.res $(HOSTOUT)
    -@cp libjgskit_64.dll $(HOSTOUT)

# Force BuildDate to be recompiled every time
#
BuildDate.obj: FORCE

FORCE:

.c.obj:
    -cl -nologo -DWINDOWS $(DEBUG_FLAGS) -c -I"$(GSKIT_HOME)/inc" -I"$(JAVA_HOME)/include" -I"$(JAVA_HOME)/include/win32" $*.c

$(JGSKIT_RC_OBJ) : $(JGSKIT_RC_SRC)
	-@rc $(BUILD_CFLAGS) -Fo$@ $(JGSKIT_RC_SRC)


clean:
	-@del $(HOSTOUT)\*.obj
	-@del $(HOSTOUT)\*.exp
	-@del $(HOSTOUT)\*.lib
	-@del $(HOSTOUT)\*.dll
	-@del $(HOSTOUT)\*.res
