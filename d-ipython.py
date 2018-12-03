#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import sys
import c
import IPython
import IPython.utils.io
import atexit, threading, ctypes
import IPython.lib.inputhook
import IPython.core.completer

evalcode = [
    # Those are printed by "python -Sc 'import sys; print(sys.modules.keys())'". encodings.utf_8 ?
    "[sys.modules[k] for k in ['zipimport', '_codecs', 'signal', 'encodings', '__builtin__', 'sys', 'encodings.aliases', 'exceptions', '_warnings', 'codecs']]",
    "[sys, sys.stdin, sys.stdout, sys.stderr, sys.modules, sys.argv, sys.modules['__builtin__'], os, os.environ]",
]

# TODO: use importnative for faster imports
evalcode += [
    "__import__('_ctypes')",
    "[v for k, v in sorted(_ctypes.__dict__.items()) if v and not isinstance(v, (dict, str, int))]",
    "__import__('_collections')",
    "[_collections.deque, _collections.defaultdict]",
    "__import__('sqlite3')",
    "__import__('_sqlite3')",
    "sqlite3.DatabaseError",
    # Used by IPython
    # "ctypes.PYFUNCTYPE(ctypes.c_int)",
]

ipybuf = c.DynamicBuffer(
    name='i',
    evalcode=evalcode,
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
        (IPython.utils.io.devnull, None),
        (IPython.lib.inputhook.guis, {}),
        (IPython.lib.inputhook.current_gui, c.noop),
        # Temporary patch out.
        (IPython.lib.inputhook.inputhook_manager.PYFUNC, None),
        (IPython.core.completer.__main__, sys.modules['__builtin__']),
    ],
)

print('serializing')
dump(IPython, ipybuf)

print('generating code')
codegen([ipybuf], modname='ipy')

v = load(pos, dbuf=ipybuf)[0]

