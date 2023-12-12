::#############################################################################
::#
::# Copyright IBM Corp. 2023
::#
::# Licensed under the Apache License 2.0 (the "License").  You may not use
::# this file except in compliance with the License.  You can obtain a copy
::# in the file LICENSE in the source distribution.
::#
::#############################################################################

@echo off
cls
@setlocal

IF NOT DEFINED JAVA_HOME (
	echo "JAVA_HOME must be set"
	goto :eof
)
IF NOT DEFINED GSKIT_32_HOME (
	echo "GSKIT_32_HOME must be set"
	goto :eof
)
IF NOT DEFINED VCVARS_32_SCRIPT (
	echo "VCVARS_32_SCRIPT must be set"
	goto :eof
)

@call "%VCVARS_32_SCRIPT%"

cd src/main/native

@call nmake -nologo -f jgskit.win32.mak clean
@call nmake -nologo -f jgskit.win32.mak

@endlocal