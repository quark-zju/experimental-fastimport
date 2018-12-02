#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import c
import sys
import struct

a = struct.Struct('>II')


print('serializing')

dump(a)

print('generating code')
codegen(modname='foo')

v = load(pos)[0]

__import__('IPython').embed()
