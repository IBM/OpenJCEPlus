###############################################################################
#
# Copyright IBM Corp. 2023
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#
###############################################################################

TOPDIR = $(MAKEDIR)\..\..\..\

PLAT = win
BUILDTOP = $(TOPDIR)\target\build$(PLAT)
HOSTOUT = $(BUILDTOP)\host32
#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system,  enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA
#DEBUG_FLAGS = -DDEBUG $(DEBUG_DETAIL)  $(DEBUG_DATA)

OBJS= $(HOSTOUT)\BasicRandom.obj \
      $(HOSTOUT)\BuildDate.obj \
      $(HOSTOUT)\CCM.obj \
      $(HOSTOUT)\Digest.obj \
      $(HOSTOUT)\DHKey.obj \
      $(HOSTOUT)\DSAKey.obj \
      $(HOSTOUT)\ECKey.obj \
      $(HOSTOUT)\ExtendedRandom.obj \
      $(HOSTOUT)\GCM.obj \
      $(HOSTOUT)\HKDF.obj \
      $(HOSTOUT)\HMAC.obj \
      $(HOSTOUT)\PKey.obj \
      $(HOSTOUT)\Poly1305Cipher.obj \
      $(HOSTOUT)\RSA.obj \
      $(HOSTOUT)\RSAKey.obj \
      $(HOSTOUT)\RsaPss.obj \
      $(HOSTOUT)\Signature.obj \
      $(HOSTOUT)\SignatureDSANONE.obj \
      $(HOSTOUT)\SignatureRSASSL.obj \
      $(HOSTOUT)\StaticStub.obj \
      $(HOSTOUT)\SymmetricCipher.obj \
      $(HOSTOUT)\Utils.obj

JGSKIT_RC_SRC = jgskit_resource.rc
JGSKIT_RC_OBJ = $(HOSTOUT)\jgskit_resource.res

TARGET = $(HOSTOUT)\jgskit.dll

all:  dircreate $(TARGET)

dircreate:
        -@mkdir $(HOSTOUT) 2>nul

$(TARGET): $(OBJS) $(JGSKIT_RC_OBJ)
        -link -dll -out:$@ $(OBJS) $(JGSKIT_RC_OBJ) -LIBPATH:"$(GSKIT_32_HOME)"\lib jgsk8iccs.lib


# Force BuildDate to be recompiled every time
#
$(HOSTOUT)\BuildDate.obj: FORCE

FORCE:

.c{$(HOSTOUT)}.obj:
        -cl -nologo -DWINDOWS $(DEBUG_FLAGS) -c -I"$(GSKIT_32_HOME)"\inc -I"$(JAVA_HOME)\include\win32" -I"$(JAVA_HOME)\include" $< -Fo$@

$(JGSKIT_RC_OBJ) : $(JGSKIT_RC_SRC)
        -@rc -Fo$@ $(JGSKIT_RC_SRC)

clean:
        -@del $(HOSTOUT)\*.obj
        -@del $(HOSTOUT)\*.exp
        -@del $(HOSTOUT)\*.lib
        -@del $(HOSTOUT)\*.dll
        -@del $(HOSTOUT)\*.res
