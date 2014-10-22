#!/usr/bin/env python
import os
import sys

start = sys.argv[1]
for root, dirs, fnames in os.walk(start):
    for fname in fnames:
        if fname.startswith('old_'):
            print 'moving', os.path.join(root, fname)
            os.rename(os.path.join(root, fname), os.path.join(root, fname[4:]))
        elif fname.endswith('.pypy-23.so'):
            print 'removing', os.path.join(root, fname)
            os.remove(os.path.join(root, fname))
