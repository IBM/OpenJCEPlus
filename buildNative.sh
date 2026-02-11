#!/bin/bash

###############################################################################
#
# Copyright IBM Corp. 2023, 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

PLATFORMS=(arm-linux64 ppc-aix64 ppcle-linux64 s390-linux64 s390-zos64 x86-linux64)

if [ -z "$JAVA_HOME" ]; 
  then 
  echo "Error: JAVA_HOME is not defined or is empty";
  exit;
fi 

if [ -z "$GSKIT_HOME" ]; 
  then 
  echo "Error: GSKIT_HOME is not defined or is empty";
  exit;
fi

if [ -z "$PLATFORM" ]; 
  then 
  echo "Error: PLATFORM is not defined or is empty";
  echo "PLATFORM should be one the following:"
  echo ${PLATFORMS[*]}
  exit;
fi

PLATFORM_FOUND=0
for plat in ${PLATFORMS[@]}; do
  if [ ${plat} == ${PLATFORM} ];
    then
    PLATFORM_FOUND=1
  fi
done

if [ ${PLATFORM_FOUND} -eq 0 ];
  then
  echo "PLATFORM ${PLATFORM} is not accepted. PLATFORM should be one the following:"
  echo ${PLATFORMS[*]}
  exit;
fi

make=make
if [ ${PLATFORM} == "ppc-aix64" ];
  then
  make=gmake
fi
cd src/main/native/ock

${make} -f jgskit.mak clean
${make} -f jgskit.mak
