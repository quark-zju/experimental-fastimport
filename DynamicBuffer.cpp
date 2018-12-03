#include "Python.h"
#include "marshal.h"
#include "pythread.h"

#include <array>
#include <chrono>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#include "windl.h"
#else
#include <dlfcn.h>
#include <unistd.h>
static void dlrefresh(){};
#endif

#define error(...) (PyErr_Format(PyExc_RuntimeError, __VA_ARGS__), -1)
#define debug(...)                                                             \
  if (debugenabled) {                                                          \
    fprintf(stderr, "[%s][%4.6f] ", name.c_str(), now() - debugstarted);       \
    fprintf(stderr, __VA_ARGS__);                                              \
    fprintf(stderr, "\n");                                                     \
    fflush(stderr);                                                            \
  }
#define len(X) (sizeof(X) / sizeof((X)[0]))

using std::string;
using std::vector;

// A thin wrapper around a C array
template <typename T> struct SizedArray {
  T *start;
  size_t len;

  inline T &operator[](size_t pos) { return start[pos]; }
  T *begin() { return start; }
  T *end() { return start + len; }
  size_t size() { return len; }
};

#define ToSizedArray(CArray)                                                   \
  (SizedArray<std::remove_reference<decltype(CArray[0])>::type>{CArray,        \
                                                                len(CArray)})

struct EvalInfo {
  string code;
  vector<uint8_t> compiled;

  // If the result is a PyList. How many items it should have.
  size_t count;
};

struct DlInfo {
  string path;
  string symbol;

  // Return 0 on error
  size_t base() {
    void *dl = dlopen(path.c_str(), RTLD_LAZY);
    if (!dl)
      return 0;
    void *addr = dlsym(dl, symbol.c_str());
    if (!addr)
      return 0;
    Dl_info info;
    if (dladdr(addr, &info) == 0)
      return 0;
    // Note: this might unload the library. The caller must make sure
    // its refcount is not 0 by calling dlopen without a dlclose.
    dlclose(dl);
    return (size_t)info.dli_fbase;
  }
};

struct DlReloc {
  uint32_t bufoffset;
  uint32_t dlindex;
};

struct ReallocReloc {
  uint32_t bufptroffset;
  uint32_t size;
};

struct TypeReadyFixup {
  uint32_t dlindex;
  uint32_t dloffset;
};

struct SubclassFixup {
  uint32_t dlindex;
  uint32_t dloffset;
  uint32_t bufoffset;
};

typedef uint32_t BufOffset;

static double now() {
  using namespace std::chrono;
  auto now = high_resolution_clock::now();
  return duration_cast<microseconds>(now.time_since_epoch()).count() / 1e6;
}

// Like the Python-side DynamicBuffer, which is a plain buffer with metadata
// about how to make PyObjects alive.  But only the de-serialization part.
struct DynamicBuffer {
  // Input
  vector<EvalInfo> evals;
  vector<DlInfo> dls;

  SizedArray<uint8_t> buf;

  SizedArray<BufOffset> bufrelocates;
  SizedArray<DlReloc> dlrelocates;
  SizedArray<BufOffset> evalrelocates;
  SizedArray<ReallocReloc> reallocrelocates;

  SizedArray<BufOffset> pylocks;
  SizedArray<TypeReadyFixup> pytypes;
  SizedArray<SubclassFixup> pysubcls;
  SizedArray<BufOffset> pymods;

  SizedArray<uint8_t> compiledimportnative;

  size_t objoffset;
  string name;

private:
  PyObject *evalvalues = NULL;
  std::vector<size_t> dlbases;
  int relocated = 0;
  int typeisready = 0;
  int debugenabled = 0;
  double debugstarted;

public:
  PyObject *getobj() {
    if (relocate())
      return NULL;
    if (typeready())
      return NULL;

    PyObject *obj = (PyObject *)(buf.start + objoffset);
    if (!obj) {
      PyErr_NoMemory();
      return NULL;
    }
    Py_INCREF(obj);
    return obj;
  }

  PyObject *getmodules() {
    if (relocate())
      return NULL;
    if (typeready())
      return NULL;

    PyObject *dict = PyDict_New();
    if (!dict)
      return NULL;
    for (size_t offset : pymods) {
      PyObject *mod = (PyObject *)(buf.start + offset);
      Py_INCREF(mod);
      const char *name = PyModule_GetName(mod);
      if (!name || PyDict_SetItemString(dict, name, mod)) {
        Py_DECREF(dict);
        return NULL;
      }
    }
    return dict;
  }

  void setdebug(int enabled) {
    if (!debugenabled && enabled)
      debugstarted = now();
    debugenabled = enabled;
  }

  int getdebug() { return debugenabled; }

  PyObject *getrawbuf() {
    return PyString_FromStringAndSize((char *)buf.start, buf.size());
  }

  PyObject *getevalcodelist() {
    PyObject *list = (PyObject *)PyList_New(evals.size());
    size_t i = 0;
    for (auto &eval : evals) {
      PyObject *item = PyString_FromString(eval.code.c_str());
      if (!item) {
        Py_DECREF(list);
        return NULL;
      }
      PyList_SET_ITEM(list, i, item);
      i += 1;
    }
    return list;
  }

  PyObject *getevalvaluelist() {
    if (relocate())
      return NULL;
    // Copy it before returning
    if (!evalvalues)
      return NULL;
    size_t size = (size_t)PyList_Size(evalvalues);
    PyObject *list = PyList_New(size);
    for (size_t i = 0; i < size; ++i) {
      PyObject *item = PyList_GET_ITEM(evalvalues, i);
      Py_INCREF(item);
      PyList_SET_ITEM(list, i, item);
    }
    return list;
  }

  bool contains(PyObject *obj) {
    uint8_t *ptr = (uint8_t *)obj;
    return (ptr >= buf.start && ptr < buf.start + buf.size());
  }

private:
  /// Check if ABI compatible. Return 0 on success.
  int check() {
    if (Py_HashRandomizationFlag) {
      return error("incompatible with PYTHONHASHSEED");
    }
    // TODO more checks?

    return 0;
  }

  int relocate() {
    if (relocated == 1) {
      return 0;
    } else if (relocated == 2) {
      return error("relocate() failed before and cannot recover");
    }

    if (check())
      return -1;

    debug("relocate: start");

    // Get pointers to set, dict dummies (place holder for deleted keys)
    PyObject *setdummy, *dictdummy;
    {
      PyObject *zero = PyInt_FromLong(0);
      PyObject *set = PySet_New(NULL);
      PyObject *dict = PyDict_New();
      if (!zero || !set || !dict)
        return error("cannot allocate test objects");
      PySet_Add(set, zero);
      PySet_Discard(set, zero);
      setdummy = ((PySetObject *)set)->table[0].key;
      PyDict_SetItem(dict, zero, zero);
      PyDict_DelItem(dict, zero);
      dictdummy = ((PyDictObject *)dict)->ma_table[0].me_key;
      if (!setdummy || !dictdummy)
        return error("unexpected Python internals");
      Py_DECREF(zero);
    }
    debug("relocate: got dummy objects");

    // Resolving library bases
    // TODO: checksum libraries ?
    for (auto &dl : dls) {
      debug("relocate:   dlopen %s", dl.path.c_str());
      dlopen(dl.path.c_str(), RTLD_LAZY);
    }
    dlrefresh();
    dlbases.clear();
    dlbases.reserve(dls.size());
    for (auto &dl : dls) {
      debug("relocate:   getting base of %s", dl.path.c_str());
      size_t base = dl.base();
      if (base == 0)
        return error("cannot get base of %s", dl.path.c_str());
      dlbases.push_back(base);
    }
    debug("relocate: got bases of %zu libraries", dls.size());

    // Eval code to get dependent objects
    {
      evalvalues = (PyObject *)PyList_New(0);

      // Append Fixed None and dummy values
      PyList_Append(evalvalues, Py_None);
      PyList_Append(evalvalues, setdummy);
      PyList_Append(evalvalues, dictdummy);

      PyObject *globals = PyEval_GetGlobals();
      PyObject *locals = PyImport_GetModuleDict();
      if (!evalvalues || !globals || !locals)
        return error("cannot allocate eval environments");

      // Prepare "imp", used by "importnative"
      if (!PyDict_GetItemString(globals, "imp")) {
        // "import imp"
        PyObject *impmod = PyImport_ImportModule("imp");
        if (!impmod)
          return -1;
        if (PyDict_SetItemString(globals, "imp", impmod))
          return error("cannot set imp to globals");
      }

      // Prepare the "importnative" function
      if (!PyDict_GetItemString(globals, "importnative")) {
        // -1: remove "\0" added by the C compiler
        PyObject *code = PyMarshal_ReadObjectFromString(
            (char *)compiledimportnative.start, compiledimportnative.len);
        if (!code)
          return error("cannot read code");
        PyObject *func = PyFunction_New(code, globals);
        if (!func)
          return error("cannot create importnative function");
        if (PyDict_SetItemString(globals, "importnative", func))
          return error("cannot set importnative to globals");
      }

      // Evalulate code!
      for (auto &eval : evals) {
        debug("relocate:   evaluating %s", eval.code.c_str());
        PyObject *code = PyMarshal_ReadObjectFromString(
            (char *)eval.compiled.data(), eval.compiled.size());
        if (!code)
          return error("cannot read compiled code: %s", eval.code.c_str());
        PyObject *value =
            PyEval_EvalCode((PyCodeObject *)code, globals, locals);
        if (!value)
          return -1;
        size_t count = 1;
        if (PyList_CheckExact(value)) {
          count = PyList_GET_SIZE(value);
          for (size_t j = 0; j < count; ++j) {
            PyObject *item = PyList_GET_ITEM(value, j);
            if (item == Py_None)
              return error("cannot have None in eval result: %s",
                           eval.code.c_str());
            item->ob_refcnt += (1 << 28);
            PyList_Append(evalvalues, item);
          }
          Py_DECREF(value);
        } else {
          count = 1;
          value->ob_refcnt += (1 << 28);
          if (value == Py_None)
            return error("cannot have None in eval result");
          PyList_Append(evalvalues, value);
        }
        if (count != eval.count)
          return error("eval count mismatch: %s", eval.code.c_str());
      }

      // Keep them referenced. So GC would not collect them. (??)
      // TODO: move it somewhere else?
      // if (mod) {
      //   PyModule_AddObject(mod, "_evalvalues", evalvalues);
      // }
    }
    debug("relocate: evaluated %zu expressions", evals.size());

    // buf[] will be modified so retrying this function will be dangerous.
    relocated = 2;

    // Fix pointers to the buffer
    assert(sizeof(size_t) == sizeof(void *));

    for (auto offset : bufrelocates) {
      size_t *ptr = (size_t *)(buf.start + offset);
      *ptr += (size_t)(buf.start);
    }
    debug("relocate: rewrote %zu buf pointers", bufrelocates.size());

    // Fix pointers to libraries
    for (auto dlreloc : dlrelocates) {
      size_t *ptr = (size_t *)(buf.start + dlreloc.bufoffset);
      *ptr += dlbases[dlreloc.dlindex];
    }
    debug("relocate: rewrote %zu library pointers", dlrelocates.size());

    // Relocate PyObject pointers to eval-ed (external) objects
    for (auto offset : evalrelocates) {
      size_t *ptr = (size_t *)(buf.start + offset);
      size_t idx = *ptr;
      PyObject *value = PyList_GET_ITEM(evalvalues, idx);
      *(PyObject **)(ptr) = value;
    }
    debug("relocate: rewrote %zu symbol pointers", evalrelocates.size());

    // Re-create PyThread_type_lock
    for (auto offset : pylocks) {
      *(PyThread_type_lock *)(buf.start + offset) = PyThread_allocate_lock();
    }
    debug("relocate: recreated %zu locks", pylocks.size());

    // Re-allocate buffers that need to be managed by the real malloc (ex.
    // PyList's items) so they can be resized properly.
    // This must be the last step.
    for (auto &reloc : reallocrelocates) {
      uint8_t *dst = (uint8_t *)PyMem_Malloc(reloc.size);
      if (!dst)
        return error("malloc failed");
      //      reloc.bufptroffset
      //           v
      // buf [ . . . . . . . . . . . . ]
      //           v       ^
      //            \_____/|<----->|
      //        points to     size (to copy)
      size_t *ptr = (size_t *)(buf.start + reloc.bufptroffset);
      uint8_t *src = (uint8_t *)(buf.start + *ptr);
      memcpy(dst, src, reloc.size);
      *(uint8_t **)(ptr) = dst;
    }
    debug("relocate: reallocated %zu buffers", reallocrelocates.size());

    relocated = 1;
    debug("relocate: done");
    return 0;
  }

  int typeready() {
    if (typeisready)
      return 0;
    relocate();

    debug("typeready: start");
    for (auto &pytype : pytypes) {
      size_t dlbase = dlbases[pytype.dlindex];
      PyTypeObject *obj = (PyTypeObject *)(dlbase + pytype.dloffset);
      if (PyType_Ready(obj))
        return -1;
    }
    debug("typeready: %zu types ready", len(pytypes));

    for (auto &subcl : pysubcls) {
      PyObject *sub = (PyObject *)(buf.start + subcl.bufoffset);
      PyTypeObject *base =
          (PyTypeObject *)(dlbases[subcl.dlindex] + subcl.dloffset);

      // Add sub as weakref to base.__subclasses__()
      // See add_subclass in typeobject.c
      PyObject *ref = PyWeakref_NewRef(sub, NULL);
      if (!ref)
        continue;
      if (base->tp_subclasses == NULL) {
        base->tp_subclasses = PyList_New(1);
        if (!base->tp_subclasses)
          return -1;
        PyList_SET_ITEM(base->tp_subclasses, 0, ref);
      } else {
        PyList_Append(base->tp_subclasses, ref);
      }
    }
    debug("typeready: %zu subclasses fixed", pysubcls.size());

    typeisready = 1;
    debug("typeready: done");
    return 0;
  }
};

// Python wrappers

typedef struct {
  PyObject_HEAD DynamicBuffer *pdbuf;
} PySerializedObject;

static PyObject *getobj(PySerializedObject *self, void *_unused) {
  return self->pdbuf->getobj();
}

static PyObject *getmodules(PySerializedObject *self, void *_unused) {
  return self->pdbuf->getmodules();
}

static PyObject *contains(PySerializedObject *self, PyObject *obj) {
  if (self->pdbuf->contains(obj)) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

static PyObject *getdebug(PySerializedObject *self, void *_unused) {
  if (self->pdbuf->getdebug()) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

static int setdebug(PySerializedObject *self, PyObject *obj, void *_unused) {
  self->pdbuf->setdebug(PyObject_IsTrue(obj));
  return 0;
}

static PyObject *getrawbuf(PySerializedObject *self, void *_unused) {
  return self->pdbuf->getrawbuf();
}

static PyObject *getevalcodelist(PySerializedObject *self, void *_unused) {
  return self->pdbuf->getevalcodelist();
}

static PyObject *getevalvaluelist(PySerializedObject *self, void *_unused) {
  return self->pdbuf->getevalvaluelist();
}

static PyMethodDef methods[] = {
    {(char *)"contains", (PyCFunction)contains, METH_O,
     (char *)"Test if an object is provided by this module"},
    {NULL, NULL, 0, NULL}};

static PyGetSetDef getsets[] = {
    {(char *)"obj", (getter)getobj, NULL,
     (char *)"Extract the single top-level object", NULL},
    {(char *)"modules", (getter)getmodules, NULL,
     (char *)"Extract all modules stored", NULL},
    {(char *)"_debug", (getter)getdebug, (setter)setdebug,
     (char *)"Enable or disable debug prints", NULL},
    {(char *)"_rawbuf", (getter)getrawbuf, NULL, (char *)"Get the raw buffer",
     NULL},
    {(char *)"_evalcodelist", (getter)getevalcodelist, NULL,
     (char *)"Get embedded eval expressions", NULL},
    {(char *)"_evalresultlist", (getter)getevalvaluelist, NULL,
     (char *)"Get results of eval expressions", NULL},
    {NULL, NULL, NULL, NULL, NULL}};

static PyObject *disablenew(PyTypeObject *subtype, PyObject *args,
                            PyObject *kwds) {
  PyErr_SetString(PyExc_RuntimeError, "cannot create instance of Serialized");
  return NULL;
}

static PyTypeObject PySerializedType = {
    PyVarObject_HEAD_INIT(NULL, 0)                  /* header */
    "Serialized",                                   /* tp_name */
    sizeof(PySerializedObject),                     /* tp_basicsize */
    0,                                              /* tp_itemsize */
    0,                                              /* tp_dealloc */
    0,                                              /* tp_print */
    0,                                              /* tp_getattr */
    0,                                              /* tp_setattr */
    0,                                              /* tp_compare */
    0,                                              /* tp_repr */
    0,                                              /* tp_as_number */
    0,                                              /* tp_as_sequence */
    0,                                              /* tp_as_mapping */
    0,                                              /* tp_hash */
    0,                                              /* tp_call */
    0,                                              /* tp_str */
    0,                                              /* tp_getattro */
    0,                                              /* tp_setattro */
    0,                                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                             /* tp_flags */
    "Serialized Buffer with fast de-serialization", /* tp_doc */
    0,                                              /* tp_traverse */
    0,                                              /* tp_clear */
    0,                                              /* tp_richcompare */
    0,                                              /* tp_weaklistoffset */
    0,                                              /* tp_iter */
    0,                                              /* tp_iternext */
    methods,                                        /* tp_methods */
    0,                                              /* tp_members */
    getsets,                                        /* tp_getset */
    0,                                              /* tp_base */
    0,                                              /* tp_dict */
    0,                                              /* tp_descr_get */
    0,                                              /* tp_descr_set */
    0,                                              /* tp_dictoffset */
    0,                                              /* tp_init */
    0,                                              /* tp_alloc */
    disablenew,                                     /* tp_new */
};
