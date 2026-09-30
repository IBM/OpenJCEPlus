@echo off
setlocal

set OPENSSL_HOME=C:\OpenSSL-v3
set OPENSSL_CONF=%OPENSSL_HOME%\openssl.cnf
set OPENJCEPLUS_PATH=C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin
set OCK_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK
set PATH=%OPENSSL_HOME%\bin;%OPENJCEPLUS_PATH%;%OCK_PATH%;%PATH%

echo Running TestOpenJCEPlus suite (OpenSSL tag only)...
echo.

mvn -Dtest=ibm.jceplus.junit.suites.TestOpenJCEPlus ^
    -Dgroups=OpenJCEPlus_OpenSSL ^
    -Dopenjceplus.library.path=%OPENJCEPLUS_PATH% ^
    -Dock.library.path=%OCK_PATH% ^
    -Dopenssl.library.path=%OPENSSL_HOME%\bin ^
    -Dopenjceplus.useOpenSSL=true ^
    -Dskip.native.compile=true ^
    -Dsurefire.useFile=false ^
    test

endlocal
