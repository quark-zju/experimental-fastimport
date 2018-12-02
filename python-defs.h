// This file will be used by both gen_cdef.py and build_cffi.py
//
// gen_cdef.py expands it to pure definitions (without macros, written in
// cpyffi-cdef.h) so cffi can parse them.
//
// build_cffi.py parses cpyffi-cdef.h to read definitions and includes this
// file in its generated C code to build the actual ffi extension.

// Public headers
#include "python2.7/Python.h"

#include "python2.7/datetime.h"
#include "python2.7/frameobject.h"
#include "python2.7/longintrepr.h"
#include "python2.7/pythread.h"
#include "python2.7/structmember.h"

// Extracted by gen_cdef.py
#include "python-structs.h"

// Extracted from Cython

typedef struct {
    PyCFunctionObject func;
#if PY_VERSION_HEX < 0x030500A0
    PyObject *func_weakreflist;
#endif
    PyObject *func_dict;
    PyObject *func_name;
    PyObject *func_qualname;
    PyObject *func_doc;
    PyObject *func_globals;
    PyObject *func_code;
    PyObject *func_closure;
    PyObject *func_classobj;
    void *defaults;
    int defaults_pyobjects;
    int flags;
    PyObject *defaults_tuple;
    PyObject *defaults_kwdict;
    PyObject *(*defaults_getter)(PyObject *);
    PyObject *func_annotations;
} __pyx_CyFunctionObject;
