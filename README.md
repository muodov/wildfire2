wildfire2
=========

Slightly improved version of self-modifying Python PoC by @0vercl0k
wildfire2 is a tool which works similar to a binary packer, but works with Python bytecode.

Basically, it wraps all the function objects in the input .pyc file so that they decrypt and patch themselves on the first call.
