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

cd src/main/native

make -f jgskit.mac.mak clean
make -f jgskit.mac.mak