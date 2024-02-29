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
IF NOT DEFINED GSKIT_HOME (
	echo "GSKIT_HOME must be set"
	goto :eof
)

:: This check for the presence of the VCVARS_64_SCRIPT was commented out since the github
:: action being used calls the equivilant of the vcvars64.bat file prior to 
:: this script being executed.

:: IF NOT DEFINED VCVARS_64_SCRIPT (
:: 	echo "VCVARS_64_SCRIPT must be set"
::	goto :eof
::)

:: @call "%VCVARS_64_SCRIPT%"

cd src/main/native

@call nmake -nologo -f jgskit.win64.cygwin.mak clean
@call nmake -nologo -f jgskit.win64.cygwin.mak

@endlocal