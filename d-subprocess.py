#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import subprocess

print('serializing')
dump(subprocess)

print('generating code')
codegen([db], modname='foo')

v = load(pos)[0]
subprocess = v

import gc
gc.disable()

proc = v.Popen(['cat'], stdin=v.PIPE, stdout=v.PIPE)
print(proc.communicate('foo'))

