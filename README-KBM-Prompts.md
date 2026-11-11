# Alien: Isolation Mixed Input 0.7 — KBM Prompts

This is the keyboard/mouse-prompt variant of Mixed Input 0.7. It retains mixed
keyboard, mouse and controller gameplay input, including native raw mouse motion,
while preferring keyboard/mouse interaction prompts.

## Choosing a variant

Install **one** `AlienIsolation.MixedInput.asi` variant:

- **Controller prompts:** prompts prefer controller bindings and glyphs even
  while keyboard or mouse input is used.
- **KBM prompts:** prompt preference remains on keyboard/mouse even while using
  the controller.

Both variants use the same installed filename and must not be installed together.
To switch, close the game and replace `AlienIsolation.MixedInput.asi` with the
file from the other package.

Actions without a usable keyboard/mouse binding retain the game's normal fallback
and can still display a controller binding. The mod does not invent bindings or
replace the game's UI.

## Installation

Copy `AlienIsolation.MixedInput.asi` beside `AI.exe`. If no ASI loader is
installed, also copy the bundled `xinput1_3.dll`.
If `xinput1_3.dll` already exists, keep the existing loader rather than
overwriting it.

This distribution build is always enabled. It reads no INI file and creates no
log file. Remove the ASI while the game is closed to disable it.

## Status

This x86 build passed 546 isolated synthetic hook tests at two relocation bases.
It has not been launched or gameplay-tested by the development tools. Manual
testing is still required for gameplay, menus, controller hotplug and special UI.

Supported `AI.exe` SHA-256:

```text
dde66521798aae8c39ed4e7a3400f561fcecfff83619d1426b9e0cedf5819a90
```
