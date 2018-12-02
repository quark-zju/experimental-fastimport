#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import c
import sys

# Patch uuid so it does not contain a reference to an opened library (which
# has dependencies on ctypes internals. Serialization of instances of ctypes
# types are not implemented).


modnames = [
    "hgext.hgsubversion",
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

print("serializing")

import ctypes, ctypes._endian, os, sys
import atexit, threading

# import uuid - uuid is no longer used
# uuid._UuidCreate = None
# uuid._uuid_generate_time = None
# uuid.lib = None

db = c.DynamicBuffer(
    evalcode=[
        # Those are printed by "python -Sc 'import sys; print(sys.modules.keys())'".
        "[sys.modules[k] for k in ['zipimport', 'encodings.__builtin__', '_codecs', 'signal', 'encodings', 'encodings.codecs', '__builtin__', 'encodings.utf_8', 'sys', 'encodings.aliases', 'exceptions', 'encodings.encodings', '_warnings', 'codecs']]",
        "[sys, sys.stdin, sys.stdout, sys.stderr, sys.modules, sys.argv, os, os.environ]",
        # native modules
        "__import__('_ctypes').__dict__.values()",
        "__import__('_collections').__dict__.values()",
    ],
    replaces=[
        (ctypes.memmove, None),
        (ctypes.memset, None),
        (ctypes._cast, None),
        (ctypes._string_at, None),
        (ctypes._wstring_at, None),
        (ctypes.pythonapi, None),
        (ctypes._endian.BigEndianStructure, None),
        (ctypes._endian.LittleEndianStructure, None),
        (ctypes._c_functype_cache, {}),
        (atexit._exithandlers, []),
        (threading._active, {}),
    ],
)

# Whitelist bser.so
c.PyModuleWriter.WHITELIST.add("bser.so")

dump(d, dbuf=db)

print("generating code")
codegen(dbuf=db, modname='foo')

if "d" in sys.argv:
    print("dump ptrmap")
    with open("ptrmap", "w") as f:
        for k, v in sorted(db.ptrmap.iteritems()):
            f.write("%d %d\n" % (k, v))

if "v" in sys.argv:
    v = load(pos, dbuf=db)

print("done")

if "i" in sys.argv:
    __import__("IPython").embed()
