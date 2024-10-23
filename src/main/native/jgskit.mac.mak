###############################################################################
#
# Copyright IBM Corp. 2023, 2024
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#
###############################################################################

TOPDIR=../../..

PLAT=mac
CFLAGS= -arch arm64 -pedantic -Wall -fstack-protector
#Setting this flag will result non key material such as handle to OCK Objects etc being logged to the trace file.
#This flag must be disabled before building production version
#DEBUG_FLAGS += -DDEBUG
#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL  -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system,  enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA =  -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS+= -g ${DEBUG_DETAIL}  ${DEBUG_DATA}

BUILDTOP = ${TOPDIR}/target/build${PLAT}
HOSTOUT = ${BUILDTOP}/aarch64
OPENJCEPLUS_HEADER_FILES ?= ${TOPDIR}/src/main/native
JAVACLASSDIR=${TOPDIR}/target/classes

OBJS= \
	${HOSTOUT}/BasicRandom.o \
	${HOSTOUT}/BuildDate.o \
	${HOSTOUT}/CCM.o \
	${HOSTOUT}/Digest.o \
	${HOSTOUT}/DHKey.o \
	${HOSTOUT}/DSAKey.o \
	${HOSTOUT}/ECKey.o \
	${HOSTOUT}/ExtendedRandom.o \
	${HOSTOUT}/GCM.o \
	${HOSTOUT}/HKDF.o \
	${HOSTOUT}/HMAC.o \
	${HOSTOUT}/PKey.o \
	${HOSTOUT}/Poly1305Cipher.o \
	${HOSTOUT}/RSA.o \
	${HOSTOUT}/RSAKey.o \
	${HOSTOUT}/RsaPss.o \
	${HOSTOUT}/Signature.o \
	${HOSTOUT}/SignatureDSANONE.o \
	${HOSTOUT}/SignatureEdDSA.o \
	${HOSTOUT}/SignatureRSASSL.o \
	${HOSTOUT}/StaticStub.o \
	${HOSTOUT}/SymmetricCipher.o \
	${HOSTOUT}/Utils.o

TARGET = ${HOSTOUT}/libjgskit.dylib

all : ${TARGET}

${TARGET} : ${OBJS}
	gcc -shared -m64 -arch arm64 -o ${TARGET} -DMAC ${OBJS} -L ${GSKIT_HOME}/lib64 -l jgsk8iccs

${HOSTOUT}/%.o : %.c
	test -d ${@D} || mkdir -p ${@D} 2>/dev/null
	gcc \
		-fPIC \
		${DEBUG_FLAGS} \
		${CFLAGS} \
		-c \
		-I${TOPDIR}/src/main/native/ \
		-I${GSKIT_HOME}/inc \
		-I${JAVA_HOME}/include \
		-I${JAVA_HOME}/include/darwin \
		-I${OPENJCEPLUS_HEADER_FILES} \
		-o $@ \
		$<

ifneq (${EXTERNAL_HEADERS},true)

${OBJS} : | headers

headers :
	echo "Compiling OpenJCEPlus headers"
	${JAVA_HOME}/bin/javac \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d ${JAVACLASSDIR} \
		-h ${TOPDIR}/src/main/native/ \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/NativeInterface.java \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/FastJNIBuffer.java \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/OCKContext.java \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/OCKException.java

endif # ! EXTERNAL_HEADERS

clean :
	rm -f ${HOSTOUT}/*.o
	rm -f ${HOSTOUT}/*.so
	rm -f ${TOPDIR}/src/main/native/com_ibm_crypto_plus_provider_ock_NativeInterface.h
	rm -f ${TOPDIR}/src/main/native/com_ibm_crypto_plus_provider_ock_FastJNIBuffer.h
	rm -f ${TOPDIR}/src/main/native/com_ibm_crypto_plus_provider_ock_OCKContext.h
	rm -f ${TOPDIR}/src/main/native/com_ibm_crypto_plus_provider_ock_OCKException.h

.PHONY : all headers clean
