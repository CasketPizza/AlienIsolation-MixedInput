# Alien: Isolation Mixed Input

Source code for the Alien: Isolation Mixed Input mod. The mod lets keyboard,
mouse, and controller input remain active together. For example, a player can
move with an analogue stick while aiming with a mouse.

Version 0.7 is provided in two prompt variants. Their mixed-input behaviour is
otherwise identical:

- **Controller Prompts** prefers controller bindings and glyphs.
- **Keyboard/Mouse Prompts** prefers keyboard and mouse bindings.

Install only one variant. The release builds are always enabled, do not read an
INI file, and do not create a log file.

## Status and supported game

This is an experimental native x86 mod for the supported Steam version of
Alien: Isolation on Windows.

Supported `AI.exe` SHA-256:

```text
dde66521798aae8c39ed4e7a3400f561fcecfff83619d1426b9e0cedf5819a90
```

The ASI checks the executable name, complete file hash, PE identity, and every
target instruction pattern before changing memory. An unsupported executable is
left untouched. No original game file is modified on disk.

## Source layout

```text
src/MixedInputControllerPrompts.cpp  Controller-prompt variant
src/MixedInputKBMPrompts.cpp         Keyboard/mouse-prompt variant
build-controller.cmd                 MSVC x86 build script
build-kbm.cmd                        MSVC x86 build script
tools/validate_controller.py         Offline controller-variant validator
tools/validate_kbm.py                Offline KBM-variant validator
```

The two C++ files are the complete runtime source for the two released ASIs.
They do not incorporate third-party source code.

## Building

### Requirements

- Windows 10 or 11
- Visual Studio 2022 Build Tools or Visual Studio 2022
- The **Desktop development with C++** workload
- MSVC x86 compiler and Windows SDK

No external C++ libraries are required. The C/C++ runtime is linked statically.

### Command-line build

Open Command Prompt or PowerShell in the repository and run:

```bat
build-controller.cmd
build-kbm.cmd
```

The scripts use Microsoft's `vswhere.exe` to locate Visual Studio and initialize
an x86 build environment. Outputs are:

```text
build/controller-prompts/AlienIsolation.MixedInput.asi
build/kbm-prompts/AlienIsolation.MixedInput.asi
```

Exact compiler commands are visible in the two build scripts. Important options
include `/O2`, `/MT`, `/W4`, `/WX`, `/GS`, Control Flow Guard, DEP, and ASLR.

### CMake build

From a Visual Studio developer environment:

```bat
cmake -S . -B cmake-build -G "Visual Studio 17 2022" -A Win32
cmake --build cmake-build --config Release
```

CMake rejects non-MSVC and non-x86 configurations because the hooks use MSVC
x86 inline assembly.

## Offline validation

Validation is optional and requires a legally installed copy of the supported
game plus Python 3:

```bat
python -m pip install -r tools/requirements.txt
python tools/validate_controller.py
python tools/validate_kbm.py
```

Place this repository in the Alien: Isolation directory as `MixedInputMod`, or
set `ALIEN_ISOLATION_DIR` to the directory containing `AI.exe`.

Each validator checks the game and plugin architecture, imports, exports,
signatures, patch boundaries, relocation handling, and the compiled hook code.
The hook code is exercised in the Unicorn x86 emulator against 546 synthetic
cases at two DLL bases. Validation never launches the game or loads the ASI.

## Installation

Copy one built `AlienIsolation.MixedInput.asi` beside `AI.exe`. An ASI loader is
also required. Nexus release archives include Ultimate ASI Loader for users who
do not already have a compatible loader.

## Licence and third-party software

The Mixed Input source is released under the MIT License; see `LICENSE`.

Ultimate ASI Loader is a separate project by ThirteenAG and is not built from or
stored in this repository. Release archives may bundle an unmodified loader
binary under its MIT License. See `THIRD_PARTY_NOTICES.md`.

## Acknowledgements

- ThirteenAG for Ultimate ASI Loader and open-source ASI examples.
- The Sevastopol patch project and Alien: Isolation modding community for prior
  input and camera research.
