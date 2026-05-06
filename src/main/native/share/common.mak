###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR=../../../..

PLAT=x86
CC ?= gcc
CFLAGS= -fPIC -Werror -std=gnu99 -pedantic -Wall -fstack-protector
LDFLAGS= -shared

ifeq (${PLATFORM},arm-linux64)
  PLAT=xr
  CFLAGS+= -DLINUX
  OSINCLUDEDIR=linux
else ifeq (${PLATFORM},ppc-aix64)
  PLAT=ap
  CC=ibm-clang_r
  CFLAGS+= -DAIX -m64
  LDFLAGS+= -m64 -brtl -blibpath:/usr/lib:lib -brwexec_must -bnoexpall \
  			-bernotok -bdatapsize:64k -btextpsize:64k -bstackpsize:64k
  OSINCLUDEDIR=aix
else ifeq (${PLATFORM},ppcle-linux64)
  PLAT=xl
  CFLAGS+= -DLINUX -m64
  LDFLAGS+= -m64
  OSINCLUDEDIR=linux
else ifeq (${PLATFORM},s390-linux64)
  PLAT=xz
  CFLAGS+= -DS390_PLATFORM -DLINUX -m64
  LDFLAGS+= -m64
  OSINCLUDEDIR=linux
else ifeq (${PLATFORM},s390-zos64)
  CC=ibm-clang64
  PLAT=mz
  CFLAGS= -DS390 -m64

  # Open XL implies strict
  # https://www.ibm.com/docs/en/open-xl-c-cpp-zos/1.1?topic=options-qstrict
  # HGPR options seems unnecessary for 64-bit environment
  # HOT option not supported
  CFLAGS+= -O3
  CFLAGS+= -fvisibility=default
  CFLAGS+= -fstack-protector-strong
  LDFLAGS= -Wl,-bAMODE=64
  OSINCLUDEDIR=zos
else ifeq (${PLATFORM},x86-linux64)
  PLAT=xa
  CFLAGS+= -DLINUX -m64
  LDFLAGS+= -m64
  OSINCLUDEDIR=linux
endif

#Setting this flag will result non key material such as handles to native contexts etc being logged to the trace file.
#This flag must be disabled before building production version
#DEBUG_FLAGS += -DDEBUG
#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL -DDEBUG_PBKDF_DETAIL -DDEBUG_PQC_KEY_DETAIL

#Setting this flag will result in sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the user that it not suitable to deploy this native library on a production system, while enabling this flag.
#This flag must be disabled before building production version.
#DEBUG_DATA = -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS+= -g ${DEBUG_DETAIL} ${DEBUG_DATA}

BUILDTOP = ${TOPDIR}/target
NATIVE_TOPDIR = ${TOPDIR}/src/main/native
OPENJCEPLUS_HEADER_FILES ?= ${NATIVE_DIR}
JAVACLASSDIR=${BUILDTOP}/classes

all : displaycompiler ${TARGET}

${TARGET} : ${OBJS}
	${CC} ${LDFLAGS} -o ${TARGET} ${OBJS} ${TARGET_LIBS}

${HOSTOUT}/%.o : %.c
	test -d ${@D} || mkdir -p ${@D}
	${CC} \
		${CFLAGS} \
		${DEBUG_FLAGS} \
		-c \
		-I${NATIVE_LIB_HOME}/inc \
		-I${JAVA_HOME}/include \
		-I${JAVA_HOME}/include/${OSINCLUDEDIR} \
		-I${OPENJCEPLUS_HEADER_FILES} \
		-o $@ \
		$<

displaycompiler :
	@echo "Compiler version: " && ${CC} --version
	@echo "Building with ${CC} compiler..."
	@echo "PLATFORM: ${PLATFORM}"
	@echo "PLAT: ${PLAT}"
	@echo "CFLAGS: ${CFLAGS}"
	@echo "LDFLAGS: ${LDFLAGS}"
	@echo "-------------------------------------"

# Force BuildDate to be compiled every time.
#
${HOSTOUT}/BuildDate.o : FORCE

FORCE :

ifneq (${EXTERNAL_HEADERS},true)

${OBJS} : | headers

headers :
	echo "Compiling OpenJCEPlus headers"
	${JAVA_HOME}/bin/javac \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d ${JAVACLASSDIR} \
		-h ${TOPDIR}/src/main/native/ock/ \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/base/FastJNIBuffer.java \
		${JNI_CLASS}; \
		if  [ "${PLATFORM}" = "s390-zos64" ]; \
			then chtag -t -c ISO8859-1 ${JNI_HEADER}; \
		fi

endif # ! EXTERNAL_HEADERS

clean :
	rm -f ${HOSTOUT}/*.o
	rm -f ${HOSTOUT}/*.so
	rm -f com_ibm_crypto_plus_provider_base_FastJNIBuffer.h
	rm -f ${JNI_HEADER}

.PHONY : all headers clean FORCE displaycompiler
