@echo off
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Installer vswhere.exe was not found.
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
if not defined VSROOT (
  echo Visual Studio 2022 C++ x86 build tools were not found.
  exit /b 1
)
if not exist "%~dp0build\controller-prompts" mkdir "%~dp0build\controller-prompts"
call "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" x86
if errorlevel 1 exit /b 1
cl /nologo /LD /std:c++17 /O2 /MT /W4 /WX /GS /guard:cf /Fo"%~dp0build\controller-prompts\MixedInputControllerPrompts.obj" "%~dp0src\MixedInputControllerPrompts.cpp" /link /OUT:"%~dp0build\controller-prompts\AlienIsolation.MixedInput.asi" /IMPLIB:"%~dp0build\controller-prompts\MixedInputControllerPrompts.lib" /PDB:"%~dp0build\controller-prompts\MixedInputControllerPrompts.pdb" /DYNAMICBASE /NXCOMPAT /guard:cf advapi32.lib
exit /b %errorlevel%
