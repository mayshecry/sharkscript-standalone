@echo off
SETLOCAL EnableDelayedExpansion


:: Usage: CALL :AppendToSystemPath "C:\path\to\add"
:AppendToSystemPath
    SET "NEW_PATH_ENTRY=%~1"
    echo Checking if "%NEW_PATH_ENTRY%" is already in system PATH...

    :: Get current system PATH from registry
    :: REG_EXPAND_SZ is for expandable strings, REG_SZ for plain strings.
    :: We need to handle both cases for the path value.
    FOR /F "tokens=2*" %%A IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') DO (
        IF "%%A"=="REG_EXPAND_SZ" (
            SET "CURRENT_SYSTEM_PATH=%%B"
        ) ELSE (
            SET "CURRENT_SYSTEM_PATH=%%A %%B"
        )
    )

    :: Check if the new entry already exists in the current system PATH
    :: Using findstr with /I (case-insensitive) and /C (literal string)
    echo !CURRENT_SYSTEM_PATH! | findstr /I /C:"%NEW_PATH_ENTRY%" >nul
    IF %ERRORLEVEL% NEQ 0 (
        echo Appending "%NEW_PATH_ENTRY%" to system PATH...
        :: setx updates the system PATH permanently. /M flag for machine-wide.
        :: Output is redirected to nul to suppress success message.
        setx PATH "%CURRENT_SYSTEM_PATH%;%NEW_PATH_ENTRY%" /M >nul
        IF %ERRORLEVEL% NEQ 0 (
            echo Warning: Failed to update system PATH. You may need to add "%NEW_PATH_ENTRY%" manually.
        ) ELSE (
            echo System PATH updated.
        )
    ) ELSE (
        echo "%NEW_PATH_ENTRY%" is already in system PATH.
    )
    GOTO :eof

:: --- Check for Administrator privileges ---
:: This command attempts to open a null session, which requires admin rights.
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo This script requires Administrator privileges to install Go and SharkScript.
    echo Please right-click the script and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: --- Go Installation ---
echo Checking for Go installation...
:: 'where go' checks if 'go.exe' is in the system PATH.
where go >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Go not found. Downloading Go 1.21.5 for Windows...
    SET "GO_VERSION=1.21.5"
    SET "GO_ARCHIVE=go%GO_VERSION%.windows-amd64.zip"
    SET "GO_URL=https://go.dev/dl/%GO_ARCHIVE%"
    SET "GO_INSTALL_DIR=C:\Go"

    :: Download Go archive using curl
    echo Downloading %GO_URL%
    curl -L -o %GO_ARCHIVE% %GO_URL%
    IF %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to download Go. Please ensure 'curl' is available and check your internet connection.
        GOTO :error_exit
    )

    :: Clean up previous installation if any
    IF EXIST "%GO_INSTALL_DIR%" (
        echo Removing existing Go installation at %GO_INSTALL_DIR%...
        rmdir /s /q "%GO_INSTALL_DIR%"
    )

    :: Extract Go archive using tar (available in modern Windows)
    echo Extracting Go to %GO_INSTALL_DIR%...
    mkdir "%GO_INSTALL_DIR%"
    :: --strip-components=1 removes the top-level 'go' directory from the archive path
    tar -xf %GO_ARCHIVE% -C "%GO_INSTALL_DIR%" --strip-components=1
    IF %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to extract Go archive. Please ensure 'tar' is available (Windows 10 build 17063+).
        GOTO :error_exit
    )

    :: Clean up downloaded archive
    del %GO_ARCHIVE%

    :: Add Go's bin directory to system PATH
    CALL :AppendToSystemPath "%GO_INSTALL_DIR%\bin"
    echo Go installed successfully.
    echo.
    echo IMPORTANT: You will need to open a NEW Command Prompt or PowerShell window
    echo for the Go environment variables to take effect.
    echo.
) ELSE (
    echo Go is already installed:
    go version
    echo.
)

:: --- SharkScript Compilation ---
echo Compiling SharkScript...
:: Check if main.go exists in the current directory
IF NOT EXIST "main.go" (
    echo Error: Run this script from the sharkscript-src root directory.
    GOTO :error_exit
)

echo Fetching dependencies...
:: Initialize Go module if go.mod doesn't exist
IF NOT EXIST "go.mod" (
    echo Initializing Go module...
    go mod init sharkscript >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo Warning: 'go mod init' failed.
    )
)
:: Explicitly get the gorilla/websocket dependency as in the original setup.sh
go get github.com/gorilla/websocket >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Warning: 'go get github.com/gorilla/websocket' failed.
)
:: Clean up unused dependencies and add missing ones
go mod tidy >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Warning: 'go mod tidy' failed. Dependencies might not be correctly resolved.
)

SET "SHS_EXE_NAME=shs.exe"
go build -o %SHS_EXE_NAME% main.go
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to compile SharkScript.
    GOTO :error_exit
)

:: --- SharkScript Installation ---
echo Installing '%SHS_EXE_NAME%' to system path...
SET "SHS_INSTALL_DIR=C:\Program Files\SharkScript"

:: Create installation directory if it doesn't exist
IF NOT EXIST "%SHS_INSTALL_DIR%" (
    mkdir "%SHS_INSTALL_DIR%"
)

:: Move the compiled executable to the installation directory
:: /Y flag overwrites without prompting
move /Y %SHS_EXE_NAME% "%SHS_INSTALL_DIR%\%SHS_EXE_NAME%"
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to move %SHS_EXE_NAME% to %SHS_INSTALL_DIR%.
    GOTO :error_exit
)

:: Add SharkScript installation directory to system PATH
CALL :AppendToSystemPath "%SHS_INSTALL_DIR%"

echo.
echo ------------------------------------------------
echo Setup Complete!
echo You can now use 'shs --compile' or 'shs --run'
echo ------------------------------------------------
echo.

:: --- Verification ---
:: Check if 'shs.exe' is now recognized in the PATH
where %SHS_EXE_NAME% >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo IMPORTANT: Please restart your terminal (Command Prompt/PowerShell)
    echo or open a new one for 'shs' command to be recognized.
) ELSE (
    echo Verification: 'shs' is active.
)

GOTO :eof

:: --- Error Handling ---
:error_exit
echo.
echo Setup failed. Please review the errors above.
echo.
pause
exit /b 1
