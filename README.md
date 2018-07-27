# Simple WoW Nonintrusive Debugger

This simple program remaps World of Warcraft memory and creates infinite loop at gives address (0x0 rebased).
Main purpose is to get around anti-debugging protection and check registers for example on function call.
Once it hits the breakpoint, WoW window will freeze. Hit any button to get registers value.
You can also attach other, normal debuggers like x64dbg or Cheat Engine to check other threads or more specific information once breakpoint is hit.
After you are done you will have to kill WoW.exe process yourself.

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
