#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import c
import sys

# Patch uuid so it does not contain a reference to an opened library (which
# has dependencies on ctypes internals. Serialization of instances of ctypes
# types are not implemented).


modnames = [
    "os",
]

def _resolvenestedmodules(mod, name):
    """resolve nested modules

    __import__('x.y.z') returns module x when no fromlist is specified.
    This function resolves it and return the module "z".
    """
    components = name.split(".")
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod

d = {}
for name in modnames:
    d[name] = _resolvenestedmodules(__import__(name), name)

print('serializing')



# Patching

import ctypes, ctypes._endian
del ctypes.memmove
del ctypes.memset
del ctypes._cast
del ctypes._string_at
del ctypes._wstring_at
del ctypes.pythonapi
ctypes._c_functype_cache.clear()
del ctypes._endian.memmove
del ctypes._endian.memset
del ctypes._endian.pythonapi
del ctypes._endian.BigEndianStructure
del ctypes._endian.LittleEndianStructure
del ctypes._endian.Structure
del ctypes.BigEndianStructure
del ctypes.LittleEndianStructure
# import uuid - uuid is no longer used
# uuid._UuidCreate = None
# uuid._uuid_generate_time = None
# uuid.lib = None

# Whitelist bser.so
c.PyModuleWriter.WHITELIST.add("bser.so")


#import ipdb
# ipdb has side effect on __builtins__
# with ipdb.launch_ipdb_on_exception():
#   pass

dump(d)


print('generating code')
codegen()

v = load(pos)

# __import__('IPython').embed()
