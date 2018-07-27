# Simple WoW Nonintrusive Debugger

This simple program remaps World of Warcraft memory and creates infinite loop at gives address (0x0 rebased).

## Getting Started

Project is written in Python 2.7 x64 and should be used under Windows.
All dependencies should be included with standard Python version.

### Installing

If you wish to compile basic program version you can do it by using pyinstaller module.

```
1. Install pyinstaller using pip
2. Navigate to destination folder in command line and execute command:
pyinstaller --onefile WoWDebugger.py
3. Pyinstaller should generate exe file in dist folder in currect directory.

```
