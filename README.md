wildfire2
=========

wildfire2 is a tool which works similar to a binary packer, but with Python bytecode instead of processor instructions.

Basically, it wraps all function objects in the input .pyc file so that they decrypt and patch themselves on the first call.
