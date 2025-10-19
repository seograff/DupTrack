@echo off
title Generador DupTrack.exe
color 1F
echo ===========================================
echo       Generador profesional DupTrack.exe
echo ===========================================
echo.

set SCRIPT=duptrack.py
set ICON=logo.ico
set IMG=logo.png
set EXE_NAME=DupTrack
set UPX_PATH=C:\Herramientas\UPX

echo Limpiando builds anteriores...
rmdir /s /q build
rmdir /s /q dist
del /q %EXE_NAME%.spec

echo Generando %EXE_NAME%.exe con PyInstaller...
pyinstaller --noconsole --onefile --icon=%ICON% --add-data "%IMG%;." --clean --name %EXE_NAME% %SCRIPT%

if exist "%UPX_PATH%\upx.exe" (
    echo Comprimiendo %EXE_NAME%.exe con UPX...
    "%UPX_PATH%\upx.exe" --best --lzma "dist\%EXE_NAME%.exe"
) else (
    echo UPX no encontrado, omitiendo compresion.
)

echo.
echo ===========================================
echo    ¡Proceso COMPLETO! Revisa dist\%EXE_NAME%.exe
echo ===========================================
pause
@echo off
title Generador DupTrack.exe
color 1F
echo ===========================================
echo       Generador profesional DupTrack.exe
echo ===========================================
echo.

set SCRIPT=duptrack.py
set ICON=logo.ico
set IMG=logo.png
set EXE_NAME=DupTrack
set UPX_PATH=C:\Herramientas\UPX

echo Limpiando builds anteriores...
rmdir /s /q build
rmdir /s /q dist
del /q %EXE_NAME%.spec

echo Generando %EXE_NAME%.exe con PyInstaller...
pyinstaller --noconsole --onefile --icon=%ICON% --add-data "%IMG%;." --clean --name %EXE_NAME% %SCRIPT%

if exist "%UPX_PATH%\upx.exe" (
    echo Comprimiendo %EXE_NAME%.exe con UPX...
    "%UPX_PATH%\upx.exe" --best --lzma "dist\%EXE_NAME%.exe"
) else (
    echo UPX no encontrado, omitiendo compresion.
)

echo.
echo ===========================================
echo    ¡Proceso COMPLETO! Revisa dist\%EXE_NAME%.exe
echo ===========================================
pause
