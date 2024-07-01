
###############################################################################
#
# Copyright IBM Corp. 2023, 2024
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#
###############################################################################

TOPDIR=./../../..

PLAT=x86
CC=gcc
CFLAGS= -fPIC
#Setting this flag will result non key material such as handle to OCK Objects etc being logged to the trace file.
#This flag must be disabled before building production version
#DEBUG_FLAGS += -DDEBUG
#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system,  enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS+= -g ${DEBUG_DETAIL}  ${DEBUG_DATA}
LDFLAGS= -shared
GSK8ICCS64=jgsk8iccs_64
GSK8ICCS=jgsk8iccs
IS64SYSTEM=
AIX_LIBPATH = /usr/lib:/lib

ifeq ($(PLATFORM),x86-linux64)
      PLAT=xa
      CFLAGS+= -DLINUX -Werror -std=gnu99 -pedantic -Wall -fstack-protector
      LDFLAGS+= -m64
      IS64SYSTEM=64
      OSINCLUDEDIR=linux
endif

ifeq ($(PLATFORM),x86-linux32)
      PLAT=xi
      CFLAGS+= -m32 -DLINUX
      LDFLAGS+= -m32
endif

ifeq ($(PLATFORM),s390-linux64)
      PLAT=xz
      LDFLAGS+= -m64
      CFLAGS+= -DS390_PLATFORM -DLINUX -Werror
      IS64SYSTEM=64
      OSINCLUDEDIR=linux
endif

ifeq ($(PLATFORM),s390-linux31)
      PLAT=xz
      CFLAGS+= -m31 -DS390_PLATFORM -DLINUX
      LDFLAGS+= -m31
endif


ifeq ($(PLATFORM),s390-zos64)
      CC=xlc
      PLAT=mz
      CFLAGS= -DS390
#      CFLAGS+= -DPKCS11_DEBUG
      CFLAGS+= -O3 -W"c,strict,hgpr,hot"
      CFLAGS+= -Wc,XPLINK,LP64,DLL,exportall
      LDFLAGS= -Wl,XPLINK,LP64,DLL,AMODE=64
      ICCARCHIVE = $(GSKIT_HOME)/libjgsk8iccs_64.x
      IS64SYSTEM=64
      OSINCLUDEDIR=zos
endif

ifeq ($(PLATFORM),s390-zos31)
      CC=xlc
      PLAT=mz

      CFLAGS= -DS390
#      CFLAGS+= -DPKCS11_DEBUG
      CFLAGS+= -O3 -W"c,strict,hgpr,hot"
      CFLAGS+= -W "c,xplink,dll,exportall"

      LDFLAGS= -W "l,xplink,dll"
      ICCARCHIVE = $(GSKIT_HOME)/libjgsk8iccs.x
      OSINCLUDEDIR=zos
endif


ifeq ($(PLATFORM),ppc-linux64)
      PLAT=xp
      CFLAGS+= -DLINUX
      LDFLAGS+= -m64
      IS64SYSTEM=64
      OSINCLUDEDIR=linux
endif

ifeq ($(PLATFORM),ppc-linux32)
      PLAT=xp
      CFLAGS+= -m32 -DLINUX
      LDFLAGS+= -m32
endif

ifeq ($(PLATFORM),ppcle-linux64)
      PLAT=xl
      CFLAGS+= -DLINUX -Werror 
      LDFLAGS+= -m64
      IS64SYSTEM=64
      OSINCLUDEDIR=linux
endif

ifeq ($(PLATFORM),ppc-aix64)
      PLAT=ap
      CC=xlc
      CFLAGS= -qcpluscmt -q64  -qpic -DAIX -Werror
      LDFLAGS= -G -q64 -blibpath:$(AIX_LIBPATH)
      IS64SYSTEM=64
      OSINCLUDEDIR=aix
endif

ifeq ($(PLATFORM),ppc-aix32)
      PLAT=ap
      CC=xlc
      CFLAGS= -qcpluscmt -q32  -qpic -DAIX
      LDFLAGS= -G -q32 -blibpath:$(AIX_LIBPATH)
endif

BUILDTOP = ${TOPDIR}/target

HOSTOUT = ${BUILDTOP}/jgskit-${PLAT}

ifeq ($(IS64SYSTEM),64)
HOSTOUT = ${BUILDTOP}/jgskit-${PLAT}-64
endif
JAVACLASSDIR=${TOPDIR}/target/classes
JCE_CLASSPATH ?= ${JAVACLASSDIR}/../ibmjceplus.jar:./../../../target/misc.jar
OBJS= ${HOSTOUT}/BasicRandom.o \
      ${HOSTOUT}/BuildDate.o \
      ${HOSTOUT}/CCM.o \
      ${HOSTOUT}/Digest.o \
      ${HOSTOUT}/DHKey.o \
      ${HOSTOUT}/DSAKey.o \
      $(HOSTOUT)/ECKey.o \
      ${HOSTOUT}/ExtendedRandom.o \
      ${HOSTOUT}/HKDF.o \
      ${HOSTOUT}/HMAC.o \
      ${HOSTOUT}/PKey.o \
      $(HOSTOUT)/Poly1305Cipher.o \
      ${HOSTOUT}/RSA.o \
      ${HOSTOUT}/RSAKey.o \
      ${HOSTOUT}/RsaPss.o \
      ${HOSTOUT}/Signature.o \
      ${HOSTOUT}/SignatureDSANONE.o \
      ${HOSTOUT}/SignatureRSASSL.o \
      ${HOSTOUT}/StaticStub.o \
      ${HOSTOUT}/SymmetricCipher.o \
      ${HOSTOUT}/GCM.o \
      ${HOSTOUT}/Utils.o \
      ${HOSTOUT}/SignatureEdDSA.o

TARGET = ${HOSTOUT}/libjgskit.so

all: dircreate javah ${SOURCES} ${TARGET}

dircreate:
	mkdir -p ${HOSTOUT}
	mkdir -p ${JAVACLASSDIR}

ifeq ($(PLAT),mz)
${TARGET}: $(OBJS)
	${CC} ${LDFLAGS} -o ${TARGET} $(OBJS) ${ICCARCHIVE}
else
${TARGET}: $(OBJS)
	${CC} ${LDFLAGS} -o ${TARGET} $(OBJS) -L ${GSKIT_HOME}/lib$(IS64SYSTEM) -l $(GSK8ICCS$(IS64SYSTEM))
endif

# Force BuildDate to be recompiled every time
#
${HOSTOUT}/BuildDate.o: FORCE

FORCE:

${HOSTOUT}/%.o: %.c
	${CC} ${CFLAGS} ${DEBUG_FLAGS} -c -I${GSKIT_HOME}/inc -I${JAVA_HOME}/include -I${JAVA_HOME}/include/${OSINCLUDEDIR} $< -o $@

javah: dircreate
	${JAVA_HOME}/bin/javac --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -cp ${JCE_CLASSPATH} \
	${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/NativeInterface.java \
	${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/FastJNIBuffer.java \
	${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/OCKContext.java \
	${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/OCKException.java \
	-d ${JAVACLASSDIR} -h ${TOPDIR}/src/main/native/

clean:
	rm -f ${HOSTOUT}/*.o
	rm -f ${HOSTOUT}/*.so
cleanAll:
	rm -rf ${TOPDIR}/target
	rm -f com_ibm_crypto_plus_provider_ock_NativeInterface.h
	rm -f com_ibm_crypto_plus_provider_ock_FastJNIBuffer.h
