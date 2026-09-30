::#############################################################################
::#
::# Copyright IBM Corp. 2025
::#
::# This code is free software; you can redistribute it and/or modify it
::# under the terms provided by IBM in the LICENSE file that accompanied
::# this code, including the "Classpath" Exception described therein.
::#############################################################################

@echo off
setlocal enabledelayedexpansion

echo ========================================
echo OpenSSL Native Build for Windows x64
echo ========================================
echo.

:: Check JAVA_HOME
IF NOT DEFINED JAVA_HOME (
    echo ERROR: JAVA_HOME must be set
    goto :error
)
echo JAVA_HOME: %JAVA_HOME%

:: Check OPENSSL_HOME
IF NOT DEFINED OPENSSL_HOME (
    echo ERROR: OPENSSL_HOME must be set
    goto :error
)
echo OPENSSL_HOME: %OPENSSL_HOME%
echo.

:: Auto-detect Visual Studio using vswhere
echo Detecting Visual Studio installation...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if not defined VS_PATH (
    echo ERROR: Could not detect Visual Studio installation
    goto :error
)

set "VCVARS_SCRIPT=!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"

if exist "!VCVARS_SCRIPT!" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property displayName`) do (
        echo Found: %%i
    )
    echo Path: !VS_PATH!
    echo.
    
    :: Initialize Visual Studio environment
    echo Initializing Visual Studio environment...
    call "!VCVARS_SCRIPT!" >nul 2>nul
    
    echo Compiler initialized
    echo.
    
    :: Navigate to native directory and build
    cd src\main\native\openssl
    
    echo ========================================
    echo Building OpenSSL native library...
    echo ========================================
    nmake -nologo -f openjceplus.win64.cygwin.mak clean
    nmake -nologo -f openjceplus.win64.cygwin.mak
    
    if errorlevel 1 (
        cd ..\..\..\..
        goto :error
    )
    
    cd ..\..\..\..
    
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL
    echo ========================================
    echo.
    echo Output: src\main\native\openssl\libopenjceplus_64.dll
    echo.

    :: Copy DLL to JVM bin directory
    echo Copying DLL to JVM bin directory...
    copy src\main\native\openssl\libopenjceplus_64.dll "%JAVA_HOME%\bin\" >nul
    if errorlevel 1 (
        echo WARNING: Failed to copy DLL to JVM bin directory
    ) else (
        echo DLL copied successfully to: %JAVA_HOME%\bin\
    )
    echo.
    
    endlocal
    exit /b 0
) else (
    echo ERROR: vcvars64.bat not found
    goto :error
)

:error
echo.
echo ========================================
echo BUILD FAILED
echo ========================================
endlocal
exit /b 1


