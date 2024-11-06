#!/bin/bash

###############################################################################
#
# Copyright IBM Corp. 2023
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#
###############################################################################

PLATFORMS=(arm-linux64 x86-linux64 x86-linux32 s390-linux64 s390-linux31 ppc-linux64 ppc-linux32 ppcle-linux64 ppc-aix64 ppc-aix32 s390-zos31 s390-zos64)

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
  echo "PLATFORM is not accepted. PLATFORM should be one the following:"
  echo ${PLATFORMS[*]}
  exit;
fi

make=make
if [ ${PLATFORM} == "ppc-aix64" ] || [ ${PLATFORM} == "ppc-aix32" ];
  then
  make=gmake
fi
cd src/main/native

${make} -f jgskit.mak clean
${make} -f jgskit.mak
