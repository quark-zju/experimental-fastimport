#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import c
import sys
import weakref

class X(list):
    pass

a = X([1,2])
w = weakref.ref(a)


print('serializing')

dump([a,w])

print('generating code')
codegen(modname='foo')

v = load(pos)

__import__('IPython').embed()
