::#############################################################################
::#
::# Copyright IBM Corp. 2026
::#
::# This code is free software; you can redistribute it and/or modify it
::# under the terms provided by IBM in the LICENSE file that accompanied
::# this code, including the "Classpath" Exception described therein.
::#############################################################################
::
::# Run full test suite: all groups, OCK + OpenSSL together.
::# Usage: run_all_tests.bat

@echo off
setlocal

set OPENSSL_HOME=C:\OpenSSL-v3
set OPENSSL_CONF=%OPENSSL_HOME%\openssl.cnf
set OPENJCEPLUS_PATH=C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin
set OCK_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK
set PATH=%OPENSSL_HOME%\bin;%OPENJCEPLUS_PATH%;%OCK_PATH%;%PATH%

echo ============================================================
echo Full test suite - all groups (OCK + OpenSSL)
echo ============================================================
echo.

mvn -Dopenjceplus.library.path=%OPENJCEPLUS_PATH% ^
    -Dock.library.path=%OCK_PATH% ^
    -Dopenssl.library.path=%OPENSSL_HOME%\bin ^
    -Dopenjceplus.useOpenSSL=true ^
    -Dskip.native.compile=true ^
    -Dsurefire.useFile=false ^
    test

set RC=%ERRORLEVEL%

echo.
if %RC%==0 (
    echo ALL TESTS PASSED
) else (
    echo TESTS FAILED [exit code %RC%]
)
echo.

endlocal
exit /b %RC%
