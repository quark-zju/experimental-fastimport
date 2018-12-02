# This file was started clean (as a better rewrite of another adhoc
# experiment). However I had to add more and more stuff here. It
# probably can be cleaned up. Some basic designs seem good, though.
# ex. "BufferPointer", and "def fields".
from cpyffi import ffi, lib

import cpyffi
import dlfcn
import marshal
import os
import signal
import struct, ctypes
import sys
import _cffi_backend

import gc

gc.disable()

addressof = ffi.addressof
cast = ffi.cast
offsetof = ffi.offsetof
typeof = ffi.typeof

# In cast ctypes._cast is deleted.
savedcast = ctypes._cast


def ctypescast(obj, typ):
    return savedcast(obj, obj, typ)


def sizeof(obj, field=None):
    """Extend sizeof to support a sub-field"""
    if field is None:
        return ffi.sizeof(obj)
    else:
        typename = typeof(addressof(obj, field)).item
        return ffi.sizeof(typename)


def string(ptr):
    if ptr == ffi.NULL:
        return "<NULL>"
    else:
        return ffi.string(ptr)


def getptrattr(ptr, fieldnameortuple, inline=False):
    if isinstance(fieldnameortuple, tuple):
        offset, typename = fieldnameortuple
        ptr = cast(typename + "[1]", ptrint(ptr) + offset)[0]
    else:
        assert isinstance(fieldnameortuple, str)
        ptr = getattr(ptr, fieldnameortuple)
    if isinstance(ptr, CFFI_TYPE) and typeof(ptr).kind == "struct":
        # Convert "struct foo &" to "struct foo *"
        ptr = addressof(ptr)
    return ptr


def debugfields(ptr):
    for fieldname in dir(ptr):
        print("%s: %s" % (fieldname, getattr(ptr, fieldname)))


def debugtype(ptr, typeptr=None, visited=None):
    if visited is None:
        visited = set()
    if typeptr is None:
        typeptr = getattr(ptr, "ob_type", None)
    if typeptr is None:
        return
    if typeptr == ffi.NULL:
        return
    tpint = ptrint(typeptr)
    if tpint in visited:
        print("cylic type detected!")
        return
    visited.add(tpint)
    flagnames = [name for name in dir(lib) if "Py_TPFLAGS_" in name]
    flags = []
    for name in flagnames:
        value = getattr(lib, name)
        if typeptr.tp_flags & value:
            flags.append(name[len("Py_TPFLAGS_") :])
    print("%d> typename: %s" % (len(visited), ffi.string(typeptr.tp_name)))
    print("       size: %d + n * %d" % (typeptr.tp_basicsize, typeptr.tp_itemsize))
    print("      flags: %s" % " | ".join(flags))
    if typeptr.tp_base != ffi.NULL:
        print("    base: %r" % typeptr.tp_base)
    debugtype(ptr, typeptr.tp_base, visited)


def dladdr(ptr):
    """Find the dynamic library containing ptr. Return (path, offset, base) or None."""
    pint = ptrint(ptr)
    dlinfo = dlfcn.ffi.new("Dl_info *")
    if dlfcn.lib.dladdr(dlfcn.ffi.cast("void *", pint), dlinfo) == 0:
        return None
    path = dlfcn.ffi.string(dlinfo.dli_fname)
    base = ptrint(dlinfo.dli_fbase)
    offset = pint - base
    return (path, offset, base)


def dlanysymbol(path):
    """Find any symbol name in the dynamic library so native code can use it to
    get the base location of the library.

    Return (name, offset, base) or raise.
    """
    cdll = ctypes.CDLL(path)
    shortname = os.path.basename(path).split(".")[0]
    # Some known libraries
    if shortname == "libpython2":
        candidates = ["Py_Main"]
    elif shortname == "libc":
        candidates = ["malloc"]
    elif shortname == "libdl":
        candidates = ["dlopen"]
    elif shortname == "libpthread":
        candidates = ["pthread_create"]
    elif shortname == "libm":
        candidates = ["sinf"]
    elif shortname == "libuuid":
        candidates = ["uuid_is_null"]
    else:
        # Python 2 extensions should have a "init<module>" symbol
        candidates = ["init%s" % shortname, "init%s" % shortname.replace("module", "")]
    # Other things to try
    for symname in candidates:
        funcptr = getattr(cdll, symname, None)
        if funcptr:
            # Verify it's the same file
            pint = ctypescast(funcptr, ctypes.c_void_p).value
            dlinfo = dladdr(pint)
            if dlinfo and dlinfo[0] == path:
                return (symname, dlinfo[1], dlinfo[2])
    raise RuntimeError("cannot guess a known symbol name from %r" % path)


_dlbasecache = {}


def dlbase(path):
    """Find the base location of a library. Return an integer or raise."""
    if path not in _dlbasecache:
        _dlbasecache[path] = dlanysymbol(path)[2]
    return _dlbasecache[path]


class UninitializedMemoryError(NotImplementedError):
    pass


# Constants

SIZEOF_VOID_P = sizeof("void *")
CFFI_TYPE = type(cast("int", 1))

# Utilities


def ptrint(ptr):
    """Convert a cffi pointer to a plain int address"""
    if isinstance(ptr, BufferPointer):
        ptr = ptr._rawptr()
    # if isinstance(ptr, CFFI_TYPE) and typeof(ptr).kind == 'struct':
    #     # Cannot cast directly. Take its address first.
    #     return ptrint(addressof(ptr))
    # else:
    return int(long(cast("uint64_t", ptr)))


def addrint(struct):
    return ptrint(addressof(struct))


def toobj(addr):
    """Convert a pointer to Python Object"""
    l = []
    if isinstance(addr, CFFI_TYPE):
        # Prevent segfault
        assert getattr(addr, "ob_type", None) is not None, "not a PyObject"
    ptr = ffi.cast("PyObject *", addr)
    ptr.ob_refcnt += 2
    lib.PyList_Append(ffi.cast("PyObject *", id(l)), ptr)
    return l[0]


def isobj(ptr):
    result = (
        getattr(ptr, "ob_type", None) is not None
        or getattr(ptr, "ht_type", None) is not None
    )
    return result


def toptr(obj):
    return PyObjectDetectTypeWriter(cast("PyObject *", id(obj)), db).ptr


def islockfree(lockptr):
    # do not block
    wait = 0
    result = lib.PyThread_acquire_lock(lockptr, wait)
    if result == 1:
        # lock taken by this acquire_lock call
        # release it before returning
        lib.PyThread_release_lock(lockptr)
        return True
    else:
        # lock already taken or taken by another thread
        assert result == 0, "unexpected PyThread_acquire_lock return value"
        return False


def ptrhint(addr):
    """Try to describe what a pointer is, by using gdb"""
    try:
        import subprocess, os

        gdbout = subprocess.check_output(
            [
                "gdb",
                "-q",
                "--batch",
                "-p",
                str(os.getpid()),
                "-ex",
                "info symbol %s" % ptrint(addr),
            ]
        )
    except Exception:
        return ""
    else:
        gdbout = "".join(l for l in gdbout.splitlines() if "in section" in l)
        if gdbout:
            gdbout = "\n\n(%s)" % gdbout
        return gdbout


# The buffer


class BufferPointer(object):
    """A pointer to DynamicBuffer. Works like a raw cffi pointer (ex. use
    setattr, getattr to read/write data). Handles buffer resize transparently.
    """

    def __init__(self, dbuf, offset, typename):
        # Bypass self.__setattr__
        setfield = super(BufferPointer, self).__setattr__
        setfield("_dbuf", dbuf)
        setfield("_offset", offset)
        # typename needs to be a pointer (or [1] array)
        if typeof(typename).kind not in {"array", "pointer"}:
            # Try to fix-up the typename so it is a pointer
            assert "[" not in typename and "*" not in typename
            typename = "%s *" % typename
        setfield("_typename", typename)

    def __getattr__(self, name, value=None):
        """Proxy getattr to the actual cffi object to read real memory"""
        return getattr(self._rawptr(), name, value)

    def writefield(self, name, value):
        """Proxy setattr to the actual cffi object to write real memory"""
        rawptr = self._rawptr()
        if isinstance(name, tuple):
            # Field not existed in the struct, in (offset, type) form
            offset, typename = name
            itemkind = typeof(typename).kind
            fieldptr = self.cast(typename, offset=offset)
            rawptr = cast("%s[1]" % typename, ptrint(rawptr) + offset)

            def setfunc(value):
                rawptr[0] = value

        else:
            # Field existed in the struct
            assert isinstance(name, str)
            itemkind = typeof(addressof(rawptr, name)).item.kind
            fieldptr = self.fieldptr(name)

            def setfunc(value):
                setattr(rawptr, name, value)

        if itemkind == "pointer":
            # Be careful! "value" might be something interesting (ex.
            # another BufferPointer, or a pointer inside libpython)
            # Use more powerful writeptr to handle them.
            fieldptr.writeptr(value)
        else:
            # Also mark the range as initialized.
            field = self.fieldptr(name)
            start = fieldptr._offset
            size = fieldptr.size()
            autopadding = self.paddingautofix(name)
            if autopadding:
                field.writeraw(b'\0' * (size + autopadding))
            setfunc(value)
            self._dbuf._markinitialized(start, size, b"s")

    __setattr__ = writefield

    def fieldptr(self, fieldname):
        """Return BufferPointer pointing to a field of the structure"""
        if isinstance(fieldname, (int, long)):
            index = fieldname
            ctypetype = typeof(self._typename)
            assert ctypetype.kind == "array"
            ptr = self._rawptr()
            offset = ptrint(ptr + index) - ptrint(ptr)
            itemtype = ctypetype.item.cname
            return self.cast(itemtype, offset)
        elif isinstance(fieldname, tuple):
            offset, typename = fieldname
            return self.cast(typename, offset)
        else:
            ptr = addressof(self._rawptr(), fieldname)
            typename = typeof(ptr).cname
            offset = self._offset + ffi.offsetof(self._typename, fieldname)
            return BufferPointer(self._dbuf, offset, typename)

    __getitem__ = fieldptr

    def writeraw(self, content):
        """Write untyped raw bytes at this offset."""
        start = self._offset
        size = len(content)
        end = start + size
        buf = self._dbuf._buf
        assert end <= len(buf)
        buf[start:end] = content
        self._dbuf._markinitialized(start, size, b"r")

    def writeptr(self, ptr, **kwargs):
        """Write pointer at this offset.
        Proxy to the more complicated DynamicBuffer.writeptr
        """
        self._dbuf.writeptr(self, ptr, **kwargs)

    def size(self):
        """Return the size of the actual object (follow pointer once)"""
        if typeof(self._typename).kind == "pointer":
            return sizeof(typeof(self._typename).item)
        else:
            return sizeof(self._typename)

    def cast(self, typename, offset=0):
        """Cast into a different type"""
        return BufferPointer(self._dbuf, self._offset + offset, typename)

    def _rawptr(self):
        """Calculate the raw cffi pointer.

        Note: The raw pointer can be invalidated by a resize of the backing
        buffer (i.e. self._dbuf._rawcharp() may change). Therefore keep it
        short-lived and recalculate frequently.
        """
        return cast(self._typename, self._dbuf._rawcharp() + self._offset)

    def __repr__(self):
        return "<BufferPointer %s at %d>" % (self._typename, self._offset)

    _paddingautofixcache = {}

    def paddingautofix(self, fieldname):
        key = (self._typename, fieldname)
        if key in self._paddingautofixcache:
            return self._paddingautofixcache[key]
        tp = typeof(self._typename)
        if tp.kind == "pointer":
            tp = tp.item
        if tp.kind == "struct":
            thisfield = None
            nextfield = None
            for name, cfield in tp.fields:
                if name == fieldname:
                    thisfield = cfield
                    continue
                elif thisfield is not None:
                    nextfield = cfield
                    break
            assert thisfield
            if nextfield is None:
                # at the struct end
                nextoffset = sizeof(tp)
            else:
                nextoffset = nextfield.offset
            padding = nextoffset - thisfield.offset - sizeof(thisfield.type)
            assert padding >= 0
            self._paddingautofixcache[key] = padding
            return padding
        else:
            return 0

def writeu32(buf, offset, value):
    buf[offset : offset + 4] = struct.pack("L", value)


def writeu64(buf, offset, value):
    buf[offset : offset + 8] = struct.pack("Q", value)


def readu32(buf, offset):
    return struct.unpack("L", buf[offset : offset + 4])[0]


def readu64(buf, offset):
    return struct.unpack("Q", buf[offset : offset + 8])[0]


readrawptr = {4: readu32, 8: readu64}[SIZEOF_VOID_P]
writerawptr = {4: writeu32, 8: writeu64}[SIZEOF_VOID_P]


def _dummies():
    # Special internal objects (dummy in setobject.c and dictobject.c)
    dummyset = {0}
    dummyset.remove(0)
    dummydict = {0: 0}
    del dummydict[0]
    dictdummy = ptrint(ffi.cast("PyDictObject *", id(dummydict)).ma_table[0].me_key)
    setdummy = ptrint(ffi.cast("PySetObject *", id(dummyset)).table[0].key)
    assert dictdummy > 0
    assert setdummy > 0
    return setdummy, dictdummy


import imp


def importnative(name, path):
    # Assumes "imp" is in globals.
    if not path:
        # Builtin
        result = imp.init_builtin(name)
        assert result, "%s should be builtin" % name
        return result
    # Load extension module with less stating or parent module checking.
    pos = name.rfind(".")
    if pos != -1:
        pname = name[:pos]
        sys = imp.init_builtin("sys")
        modules = sys.modules
        if pname not in modules:
            modules[pname] = type(sys)(pname)
            result = imp.load_dynamic(name, path)
            del modules[pname]
            return result
    return imp.load_dynamic(name, path)


# lib._PyImport_LoadDynamicModule('hgext.extlib.linelog', path, ffi.cast('PyFileObject*', id(f)).f_fp)


class DynamicBuffer(object):
    """Buffer with relocate ability"""

    if "nt" in sys.modules:
        dlfcn.lib.dlrefresh()

    LIBPYTHON_NAME = dladdr(id(None))[0]

    def __init__(self, name, evalcode=(), replaces=()):
        assert name.isalnum()
        self.name = name
        self._evalcode = evalcode = [
            # Must use a reference to __builtins__ in globals(). "__builtins__"
            # cannot be serialized. Otherwise code will be in "restricted"
            # mode.  See PyFrame_New and PyEval_GetRestricted.
            "__builtins__"
        ] + list(evalcode)

        # 3 special values in evalvalues
        self._evalvalues = evalvalues = [None, toobj(SET_DUMMY), toobj(DICT_DUMMY)]
        noneindex = 0

        evalcounts = []
        for code in evalcode:
            locals = sys.modules
            val = eval(code, globals(), locals)
            if isinstance(val, list):
                assert val is not None
                evalvalues += val
                evalcounts.append(len(val))
            else:
                assert val is not None
                evalvalues.append(val)
                evalcounts.append(1)
        self._evalcounts = evalcounts

        # Python ID -> evalvalues index
        symbolmap = {}
        for i, val in enumerate(evalvalues):
            if id(val) not in symbolmap:
                symbolmap[id(val)] = i
        self._symbolmap = symbolmap

        # Handle "nullify". Also make sure this object itself (and the module)
        # are nullified to avoid trouble!
        repalces = list(replaces[:]) + [
            (_cffi_backend, None),
            (cpyffi, None),
            (dlfcn, None),
            (ffi, None),
            (globals(), {}),
            (lib, None),
            (self, None),
            (self.__dict__, {}),
            (type(self), None),
        ]
        # Sanity check
        for k, v in replaces:
            if k is None or isinstance(k, int) or isinstance(k, str):
                raise AssertionError(
                    "replaces cannot have atomic types: %r => %r" % (k, v)
                )
        # Object ID -> Object
        self.replacemap = {id(k): v for k, v in replaces}

        # Main buffer
        self._buf = bytearray()
        # Real address -> Local offset (ex. Already serialized objects)
        self.ptrmap = {}
        # Track "uninitialized" range
        self._initialized = bytearray(b"1" * len(self._buf))

        # Pointers (related to buf start) needed to be rewritten.
        # Need to add buffer start address
        self._bufoffsetset = set()
        # Need to add library address
        self._dlnames = []  # dynamic library names
        self._dloffsets = []  # (bufoffset, dlnameindex)
        self._dloffsetset = set()
        # Need to resolve symbols
        self._symoffsetset = set()
        # Need to allocate locks
        self._pylocks = []
        # Need to redo malloc so the region is maintained by malloc.
        self._realloc = []
        # Need PyType_Ready (native static types)
        self._pytypeset = set()  # (dlindex, dloffset)
        # Modules
        self._pymodset = set()
        # GC offsets
        self._gcoffsets = []
        # Subclass fixups (dlindex, dloffset, bufoffset)
        self._subclassfixups = []

    def firstobjoffset(self):
        # The first (top) object
        return min(self.ptrmap.values())

    def toptr(self, offset, typename="PyObject *"):
        return BufferPointer(self, offset, typename)

    def extendraw(self, content, initialized=False):
        """Extend the buffer using content. Return the offset of it.

        If initialized is True, mark the range as initialized.
        Otherwise it's not initialized and can be detected by ensureinitialized.
        """
        offset = len(self._buf)
        self._buf += content
        if initialized:
            # '_' is just a non-zero value.
            self._initialized += b"_" * len(content)
        else:
            self._initialized += b"\0" * len(content)
        return offset

    def ensureinitialized(self, start=0, size=None, offsettablefunc=None):
        """Test if the range has been initialized. Raise if not.
        offsettable is a "relative offset -> name" map that is used to print
        debug message.
        """
        assert len(self._initialized) == len(self._buf)
        if size is None:
            end = len(self._buf)
        else:
            end = start + size
        for i, b in enumerate(self._initialized[start:end]):
            if not b:
                if size < 1024:
                    msg = "Offset %d is not initialized:\n" % i
                    # verbose debug message
                    offsettable = offsettablefunc()
                    for j in xrange(size):
                        inited = self._initialized[j + start]
                        if not inited:
                            inited = "(not initialized)"
                        else:
                            inited = "(initialized by %c)" % inited
                        msg += "\n %5d> %02x %s" % (j, self._buf[j + start], inited)
                        if offsettable:
                            symname = offsettable.get(j)
                            if symname:
                                msg += " (%s)" % symname
                    print(msg)
                raise UninitializedMemoryError("uninitialized memory")

    def _markinitialized(self, start, size, ch=b"i"):
        self._initialized[start : start + size] = ch * size

    def mallocat(self, offset, size, needrealloc=True):
        """Malloc "size" bytes. Write pointer to "offset".
        If the memory region might be used by libc realloc, set "needrealloc"
        to True.
        """
        offset = self._normalizeoffset(offset)
        base = self.extendraw(b"\xcc" * size)
        self._writerawptr(offset, base)
        if needrealloc:
            self._realloc.append((offset, size))
        else:
            self._appendbufoffsets(offset)
        return base

    def replaceptr(self, ptr):
        """Replace ptr with a user-defined replacement"""
        pint = ptrint(ptr)
        if pint in self.replacemap:
            return toptr(self.replacemap[pint])
        else:
            return ptr

    def hasptr(self, ptr, checkptrmap=True, checksymbolmap=True, checklibpython=True):
        """Test if a pointer is known"""
        pint = ptrint(ptr)
        if (checkptrmap and pint in self.ptrmap) or (
            checksymbolmap and pint in self._symbolmap
        ):
            return True
        # If ptr is a Python object, it might be allocated by PyObject_Malloc.
        # In that case, we should return False. Ideally libpython is recompiled
        # so it won't have static pools.
        if checklibpython and dladdr(pint) is not None:
            return True

    def writeptr(self, offset, ptr, reallocsize=0):
        """Write a few kinds of pointers.

        The pointer could be a local offset (BufferPointer), or a real pointer
        in libraries (ex. a C function, static objects like Py*_Type, None,
        True, False).

        The ptr will be converted to a relative address, and a rule to rewrite
        it will be added.

        If reallocsize is not 0, the memory pointed by the pointer (must be
        within self._buf, aka. ptr must be a BufferPointer) will be marked as
        needed to be allocated by malloc.
        """
        offset = self._normalizeoffset(offset)
        # print("writebodyat %r %r" % (offset, ptr))

        if isinstance(ptr, BufferPointer):
            # Pointer to self._buf
            self._writerawptr(offset, ptr._offset)
            if reallocsize > 0:
                self._realloc.append((offset, reallocsize))
            else:
                self._appendbufoffsets(offset)
            return

        pint = ptrint(ptr)
        if pint == 0:
            self._writerawptr(offset, pint)
            return

        dlinfo = dladdr(pint)
        if pint in self.ptrmap:
            # Previously written. Convert from Python object address to a local
            # address.
            assert dlinfo is None, (
                "Local pointer and library %s pointer overlaps" % dlinfo[1]
            )
            assert reallocsize == 0, "Existing object cannot be moved"
            self._writerawptr(offset, self.ptrmap[pint])
            self._appendbufoffsets(offset)
        elif pint in self._symbolmap:
            # Defined symbol (ex. Pointer to an evalcode native module)
            assert reallocsize == 0, "Symbol cannot be moved"
            symbolid = self._symbolmap[pint]
            self._writerawptr(offset, symbolid)
            assert offset not in self._symoffsetset
            self._symoffsetset.add(offset)
        elif dlinfo is not None:
            assert reallocsize == 0, "Pointer in libpython cannot be moved"
            dlpath, dloffset = dlinfo[0], dlinfo[1]
            self._writerawptr(offset, dloffset)
            isobj = getattr(ptr, "ob_refcnt", None) is not None
            self._appenddloffset(offset, dlpath, isobj)
            # In a library (ex. C functions, None, True, etc)
            # Note: If it's a PyType. Then we should check if it needs
            # PyType_Ready.
            self.marktype(ptr, dlinfo)
        else:
            msg = "Unknown pointer: %r%s" % (ptr, ptrhint(ptr))
            raise TypeError(msg)

    def writeweakrefptr(self, offset, objptr):
        """If obj was stored in this buffer, write its pointer at offset.
        Otherwise do nothing. Used by weakrefs.

        This is similar to writeptr. But writes None in case: 1. dlinfo
        points to an unknown library. 2. pointer is unknown.
        """
        with open("weaklog", "a") as f:
            offset = self._normalizeoffset(offset)
            pint = ptrint(objptr)
            assert pint != 0
            f.write("pint = %d\n" % pint)
            assert isinstance(objptr, CFFI_TYPE)
            # Another object serialized?
            if pint in self.ptrmap:
                f.write(" in ptrmap as %d\n" % self.ptrmap[pint])
                self._writerawptr(offset, self.ptrmap[pint])
                self._appendbufoffsets(offset)
                return
            if pint in self._symbolmap:
                symbolid = self._symbolmap[pint]
                f.write(" pint in sym map as %s\n" % symbolid)
                self._writerawptr(offset, symbolid)
                assert offset not in self._symoffsetset
                self._symoffsetset.add(offset)
                return
            # Pointing to a KNOWN library? (ex. "dict")
            dlinfo = dladdr(pint)
            if dlinfo:
                f.write(" in dl %r\n" % (dlinfo,))
                dlpath, dloffset = dlinfo[0], dlinfo[1]
                if dlpath in self._dlnames:
                    f.write("  in known dl\n")
                    self._writerawptr(offset, dloffset)
                    self._appenddloffset(offset, dlpath, isobj=True)
                    return
            # Make the weakref dead (None)
            f.write(" unknown\n")
            symbolid = 0
            assert self._evalvalues[symbolid] is None
            self._writerawptr(offset, symbolid)
            assert offset not in self._symoffsetset
            self._symoffsetset.add(offset)

    def writegcheader(self):
        self._gcoffsets.append(len(self._buf))
        header = ffi.new("PyGC_Head *")
        header.gc.gc_refs = lib._PyGC_REFS_UNTRACKED
        self.extendraw(ffi.buffer(header), initialized=True)

    def allocatelock(self, offset):
        offset = self._normalizeoffset(offset)
        self._writerawptr(offset, 0)
        assert offset not in self._pylocks
        self._pylocks.append(offset)

    def appendevalcode(self, code, value=None):
        if value is None:
            value = eval(code)
        assert not isinstance(value, list)
        self._symbolmap[id(value)] = len(self._evalvalues)
        self._evalcode.append(code)
        self._evalvalues.append(value)
        self._evalcounts.append(1)

    def addsubclassfixup(self, offset, baseptr):
        offset = self._normalizeoffset(offset)
        dlinfo = dladdr(baseptr)
        assert dlinfo is not None, "Base class should be known at this point"
        dlpath, dloffset = dlinfo[0], dlinfo[1]
        dlindex = self._dlnames.index(dlpath)
        self._subclassfixups.append((dlindex, dloffset, offset))

    def markmodule(self, offset):
        """Mark a ptr as a module. This does not affect correctness. But
        provides a way to list all modules serialized.
        """
        offset = self._normalizeoffset(offset)
        self._pymodset.add(offset)

    def marktype(self, typeptr, dlinfo=None):
        """Mark a type as need to be PyType_Ready

        Do nothing if typeptr is not a 'PyTypeObject *' or it does not need
        PyType_Ready, or it is already marked. Return True if the type is newly
        marked.
        """
        istype = hasattr(typeptr, "tp_flags") or hasattr(typeptr, "ht_type")
        if not istype:
            # Double check
            obtype = getattr(typeptr, "ob_type", None)
            if obtype and obtype == lib.PyType_Type:
                istype = True
        if not istype:
            return False
        if dlinfo is None:
            dlinfo = dladdr(typeptr)
            # If the .so is imported. Then it's unnecessary to call
            # PyType_Ready.
            if dlinfo is None:
                return False
        dlpath, dloffset = dlinfo[0], dlinfo[1]
        if dlpath == DynamicBuffer.LIBPYTHON_NAME:
            # Assume all types in libpython are already "Ready"
            return False
        try:
            dlindex = self._dlnames.index(dlpath)
        except ValueError:
            return False
        else:
            if (dlindex, dloffset) in self._pytypeset:
                return False
            else:
                self._pytypeset.add((dlindex, dloffset))
                return True

    def _normalizeoffset(self, offset):
        """Convert BufferPointer to a plain int offset"""
        if isinstance(offset, (int, long)):
            return offset
        elif isinstance(offset, BufferPointer):
            return offset._offset
        else:
            raise TypeError("Not an offset type: %r" % offset)

    def _writerawptr(self, offset, value):
        self._initialized[offset : offset + SIZEOF_VOID_P] = b"p" * SIZEOF_VOID_P
        writerawptr(self._buf, offset, value)

    def _readrawptr(self, offset):
        return readrawptr(self._buf, offset)

    def _rawcharp(self):
        """Raw "char *" pointer to self._buf content"""
        return cast("PyByteArrayObject *", id(self._buf)).ob_bytes

    def _appendbufoffsets(self, offset):
        assert offset not in self._bufoffsetset, "Double write detected"
        self._bufoffsetset.add(offset)

    def _appenddloffset(self, offset, dlpath, isobj):
        assert offset not in self._dloffsetset, "Double write detected"
        try:
            dlindex = self._dlnames.index(dlpath)
        except ValueError:
            dlindex = len(self._dlnames)
            self._dlnames.append(dlpath)
            if "cffi_backend" in dlpath:
                raise NotImplementedError("cffi_backend shouldn't be included!")
        self._dloffsetset.add(offset)
        self._dloffsets.append((offset, dlindex))


# How to write types to the buffer


class PtrWriter(object):
    """Define how to write a pointer to DynamicBuffer"""

    TYPENAME = None
    DEBUGSTACK = []

    # Write functions that have requested to write at the end.
    # They should not add new DEFERREDWRITES objects.
    DEFERREDWRITES = []

    def __init__(self, ptr, dbuf):
        if self.TYPENAME:
            ptr = cast(self.TYPENAME, ptr)
        self.ptr = ptr
        self.dbuf = dbuf
        self.typename = ffi.typeof(ptr).cname  # ex. "PyXxxObject *"
        self._offsettable = {}
        self.DEBUGSTEP = ""

    def size(self):
        """Bytes needed for the main struct"""
        if typeof(self.typename).kind == "pointer":
            # Resolve pointer for one level automatically
            # (TYPENAME is usually a pointer)
            return sizeof(typeof(self.typename).item)
        else:
            # If TYPENAME is not a pointer, just return its size.
            # Non-pointer types can be useful to write inline.
            return sizeof(self.typename)

    def write(self):
        """Write the object in buffer. Return the offset.
        Do not write twice if already written.
        """
        # Already written?
        pint = ptrint(self.ptr)
        offset = self.dbuf.ptrmap.get(pint)
        if offset is None:
            assert not self.existed(), "cannot write known pointers %r" % self.ptr
            size = self.size()
            self.maybewriteheader()
            offset = self.dbuf.extendraw(b"\xcc" * size)
            self.maybewritefooter()
            self.dbuf.ptrmap[pint] = offset
            self.DEBUGSTACK.append(self)
            newptr = self.dbuf.toptr(offset, self.typename)
            # Might call write again
            try:
                self.writebodyat(newptr)
                self.postwritefixup(newptr)
                self.dbuf.ensureinitialized(offset, size, self.offsettable)
            except (
                NotImplementedError,
                UninitializedMemoryError,
                AttributeError,
                KeyError,
            ):
                import traceback

                traceback.print_exc()
                print("\nWriter stack:")
                self.debugstack()
                print("\nType information:")
                debugtype(self.ptr)
                msg = (
                    "\nError happened when serializing %s at 0x%x.\n"
                    "Errors are often caused by instances of an unknown native type.\n"
                ) % (self.typename, ptrint(self.ptr))
                print(msg)
                sys.exit(-1)
            self.DEBUGSTACK.pop()
            if not self.DEBUGSTACK:
                # The root pointer is written.
                # Now write deferred objects (ex. weakrefs).
                for func in self.DEFERREDWRITES:
                    func()
                self.DEFERREDWRITES[:] = []
        return BufferPointer(self.dbuf, offset, self.typename)

    def writebodyat(self, orignewptr):
        """Write the actual content body of *typename (or typename, if it's not
        a pointer) to the given offset. The destination should be already
        allocated.
        """
        # Extra fields specified to certain objects.
        fields = self.fields()
        # Useful for CAST action.
        caststack = []
        # Write them
        for args in fields:
            # print(args)
            ptr = self.ptr
            newptr = orignewptr
            assert isinstance(ptr, CFFI_TYPE)
            assert isinstance(newptr, BufferPointer)
            if caststack:
                ptr = cast(caststack[-1], ptr)
                newptr = newptr.cast(caststack[-1])
            rootnewptr = newptr
            rootptr = ptr
            # Resolve names like "x.y.z" (used by PyHeapTypeWriter)
            fullname, action = args[:2]
            self.DEBUGSTEP = "%s %s" % (action, fullname)
            name = fullname
            if isinstance(name, str):
                while "." in name:
                    prefix, name = name.split(".", 1)
                    ptr = getptrattr(ptr, prefix)
                    newptr = newptr.fieldptr(prefix)
            else:
                # name is (offset, typename) for a unknown field
                pass
            assert isinstance(newptr, BufferPointer)
            args = args[2:]
            if action is Action.ASSIGN:
                value = args[0]
                newptr.writefield(name, value)
            elif action is Action.ASSIGN_FIELD_PTR:
                ptrname = args[0]
                value = rootnewptr.fieldptr(ptrname)
                newptr.writefield(name, value)
            elif action is Action.ASSIGN_OFFSET_PTR:
                offset = args[0]
                value = newptr.cast("char[%d]" % (offset + 1))[offset]
                newptr.writefield(name, value)
            elif action is Action.COPY:
                value = getptrattr(ptr, name)
                newptr.writefield(name, value)
            elif action is Action.RAW:
                content = args[0]
                newptr.fieldptr(name).writeraw(content)
            elif action is Action.CAST:
                assert name
                caststack.append(name)
            elif action is Action.CASTEND:
                caststack.pop()
            elif action in {
                Action.CLONE_PTR,
                Action.CLONE_PTR_INPLACE,
                Action.CLONE_PTR_REALLOC,
                Action.CLONE_PTR_SHALLOW,
            }:
                value = getptrattr(ptr, name)
                newfieldptr = newptr.fieldptr(name)
                if value == ffi.NULL:
                    # Just write a NULL regardless of REALLOC.
                    # But this makes no sense for POINTER_INPLACE because the
                    # length of INPLACE write is unknown.
                    assert action != Action.CLONE_PTR_INPLACE
                    newfieldptr.writeptr(value)
                else:
                    # CLONE_PTR_SHALLOW requires the value to exist in a library,
                    # or in symbol table (ex. tp_new of Random_Type)
                    # Otherwise it's not different from CLONE_PTR
                    if action is Action.CLONE_PTR_SHALLOW:
                        pint = ptrint(value)
                        if pint not in self.dbuf._symbolmap and dladdr(pint) is None:
                            raise TypeError(
                                "field %s in %r: %r is not in libraries or symtable%s"
                                % (fullname, self.ptr, value, ptrhint(value))
                            )
                    wtype, wargs = (args + (None, None))[:2]
                    inline = action is Action.CLONE_PTR_INPLACE
                    realloc = action is Action.CLONE_PTR_REALLOC
                    cloneptr(newfieldptr, value, wtype, wargs, inline, realloc)
            elif action is Action.CLONE_LOCK:
                value = getptrattr(ptr, name)
                if not islockfree(value):
                    raise NotImplementedError("cannot clone non-free lock")
                newfieldptr = newptr.fieldptr(name)
                self.dbuf.allocatelock(newfieldptr)
            else:
                raise TypeError("Unknown action: %r" % action)
        self.DEBUGSTEP = ""

    def postwritefixup(self, newptr):
        pass

    def writeptrat(self, offset, **kwargs):
        """Make offset a pointer to this object. Write object if needed.

        Unlike "write", this handles more cases where the actual write
        (writebodyat) can be skipped. For example, if "self.ptr" points to a known
        symbol.

        Unlike "writebodyat", this writes a pointer instead of the actual object
        body.
        """
        assert isinstance(offset, BufferPointer)
        if self.ptr == ffi.NULL or self.existed():
            offset.writeptr(self.ptr, **kwargs)
        else:
            offset.writeptr(self.write(), **kwargs)

    def maybewriteheader(self):
        """Write optional header that is not part of the main object"""

    def maybewritefooter(self):
        """Write optional footer that is not part of the main object"""

    def existed(self):
        """Does the object exist in libraries (ex. None) or in self.dbuf?"""
        return self.dbuf.hasptr(self.ptr)

    def fields(self):
        """Declarative way of saying what to serialize"""
        raise NotImplementedError("implement this!")

    def offsettable(self):
        """{offset: name} used for debug messages"""
        base = ptrint(self.ptr)

        def listfields(ptr):
            try:
                return [name for name, _field in typeof(ptr).item.fields]
            except Exception:
                return []

        def visit(ptr, prefix):
            fields = listfields(ptr)
            for fieldname in fields:
                field = addressof(ptr, fieldname)
                fieldprefix = prefix[:] + [fieldname]
                visit(field, fieldprefix)
            else:
                offset = ptrint(ptr) - base
                desc = " -> ".join(prefix)
                self.mergeoffsettable([(offset, desc)])

        visit(self.ptr, [self.humantypename()])
        return self._offsettable

    def mergeoffsettable(self, items):
        table = self._offsettable
        for offset, name in items:
            if offset in table:
                if name not in table[offset]:
                    table[offset] += ", %s" % name
            else:
                table[offset] = name
        return table

    def humantypename(self):
        return self.typename

    @staticmethod
    def debugstack(stack=None):
        if stack is None:
            stack = PtrWriter.DEBUGSTACK
        for i, writer in enumerate(stack):
            try:
                obj = toobj(writer.ptr)
                humandesc = repr(obj)
            except Exception:
                humandesc = ""
            if humandesc:
                if len(humandesc) > 100:
                    humandesc = humandesc[:100] + "..."
            else:
                humandesc = "%s at %x" % (
                    writer.typename or "something",
                    ptrint(writer.ptr),
                )
            print("%d> %s" % (i, humandesc))
            print("  Writer: %r" % (writer,))
            print("    Step: %s" % (writer.DEBUGSTEP,))


class Action(object):
    """Action to fields of a Python object"""

    # Assign using the given value (arg1)
    # For pointers, they will be processed with extra care. See
    # BufferPointer.__setitem__ and DynamicBuffer.writeptr.
    ASSIGN = "ASSIGN"

    # Assign to a pointer of another field (arg1: field name)
    ASSIGN_FIELD_PTR = "ASSIGN_FIELD_PTR"

    # Assign to a pointer offset (arg1) by the start of the struct.
    ASSIGN_OFFSET_PTR = "ASSIGN_OFFSET_PTR"

    # Copy field from the original object (for plain fields, no args)
    COPY = "COPY"

    # Override the field using raw bytes (arg1). The raw bytes can
    # have a length that is greater than the actual field. Useful
    # for embedded raw contents, like strings.
    RAW = "RAW"

    # Recursively write the content pointed by the original pointer.
    # The type of the pointer is usually detected automatically.
    # arg1, arg2 are optional. They specify the writer type and arguments.
    # Useful for uncommon types (ex. not a PyObject).
    CLONE_PTR = "CLONE_PTR"

    # Similar to CLONE_PTR, but mark the new object as "need realloc".
    # So the pointer to it will be managed by libc allocator.
    # Useful for anything that might be libc "realloc()"-ed.
    CLONE_PTR_REALLOC = "CLONE_PTR_REALLOC"

    # Similar to CLONE_PTR, but write in-place without allocating
    # memory for the new (immediate) structure. Useful when special
    # fields are embedded in a bigger struct.
    #
    # For example, tuple and list have this difference. PyTuple embeds
    # a list of "PyObject *" at the end of its struct (i.e. PyTupleObject
    # has "PyObject *ob_item[1]", "[1]" means embedded). PyList has a
    # pointer to an allocated list of "PyObject *" (i.e. PyListObject
    # has "PyObject **ob_item", the second "*" means pointing to
    # an evalcode buffer). Therefore tuple uses CLONE_PTR_INPLACE, and
    # list needs CLONE_PTR. Because list also has resize requirement,
    # it uses CLONE_PTR_REALLOC.
    CLONE_PTR_INPLACE = "CLONE_PTR_INPLACE"

    # Similar to CLONE_PTR, but make sure it's a shallow clone - no new objects
    # are written. Same as COPY but with better errors.
    CLONE_PTR_SHALLOW = "CLONE_PTR_SHALLOW"

    # Clone a "PyThread_type_lock" type.
    # Lock must be released.
    CLONE_LOCK = "CLONE_LOCK"

    # Cast points to given typename (use fieldname as typename)
    CAST = "CAST"

    # Pop up CAST stack.
    CASTEND = "CASTEND"


class CArrayWriter(PtrWriter):
    """Write a C array. Suitable for fields like 'char * x'."""

    def __init__(self, ptr, dbuf, count, itemtype):
        """ptr points to the start of an array"""
        typename = "%s[%d]" % (itemtype, count)
        ptr = cast(typename, ptr)
        super(CArrayWriter, self).__init__(ptr, dbuf)
        assert self.size() == sizeof(itemtype) * count

    def writebodyat(self, newptr):
        # newptr points to the the allocated space.
        newptr.writeraw(ffi.buffer(self.ptr)[:])


class PyObjectArrayWriter(PtrWriter):
    """Write a list of PyObject pointers. For fields like 'PyObject *x[1]'."""

    def __init__(self, ptr, dbuf, count):
        """ptr points to the first PyObject"""
        self.count = count
        typename = "PyObject *[%d]" % (count)
        assert sizeof(typename) == SIZEOF_VOID_P * count
        ptr = cast(typename, ptr)
        super(PyObjectArrayWriter, self).__init__(ptr, dbuf)

    def writebodyat(self, newptr):
        # Use cloneptr to write actual objects.
        for i in xrange(self.count):
            cloneptr(newptr[i], self.ptr[i])


class NullTerminatedArrayWriter(PtrWriter):
    """Write an array of struct. The array ends with an item of all 0s.
    Useful for fields like 'formatdef *' (actually 'formatdef[n]' where n is
    calculated).
    """

    ITEMTYPE = None
    CLONEARGS = None

    def __init__(self, ptr, dbuf, itemtype=None, itemcloneargs=None):
        """ptr points to the start of an array"""
        if not itemtype:
            itemtype = self.ITEMTYPE
        assert itemtype

        # Count it
        countptr = cast("%s *" % itemtype, ptr)
        count = 0
        itemsize = sizeof(itemtype)
        while True:
            itemptr = countptr + count
            if ffi.buffer(itemptr, SIZEOF_VOID_P)[:] == b"\0" * SIZEOF_VOID_P:
                count += 1
                break
            count += 1
        self.count = count
        self.itemtype = itemtype
        self.itemcloneargs = itemcloneargs or self.CLONEARGS or {}
        typename = "%s[%d]" % (itemtype, count)
        ptr = cast(typename, ptr)
        super(NullTerminatedArrayWriter, self).__init__(ptr, dbuf)
        assert self.size() == sizeof(itemtype) * count

    def writebodyat(self, newptr):
        # Use cloneptr to write actual objects.
        for i in xrange(self.count):
            # Note: inline is needed (used "self.ptr + i", not "self.ptr[i]")
            cloneptr(newptr[i], self.ptr + i, inline=True, **self.itemcloneargs)


class SetEntryArrayWriter(PtrWriter):
    """Write setentry[]"""

    def __init__(self, ptr, dbuf, count):
        self.count = count
        typename = "setentry[%d]" % count
        assert sizeof(typename) == sizeof("setentry") * count
        ptr = cast(typename, ptr)
        super(SetEntryArrayWriter, self).__init__(ptr, dbuf)

    def writebodyat(self, newptr):
        for i in xrange(self.count):
            newptr[i].hash = self.ptr[i].hash
            key = self.ptr[i].key
            if key == ffi.NULL or ptrint(key) == SET_DUMMY:
                # Need to write as a symbol
                newptr[i].key = key
            else:
                # Maybe need to copy "key"
                cloneptr(newptr[i].fieldptr("key"), key)


class DictEntryArrayWriter(PtrWriter):
    """Write PyDictEntry[]"""

    def __init__(self, ptr, dbuf, count):
        assert lib.Py_HashRandomizationFlag == 0, "Does not work with PYTHONHASHSEED"
        self.count = count
        typename = "PyDictEntry[%d]" % count
        assert sizeof(typename) == sizeof("PyDictEntry") * count
        ptr = cast(typename, ptr)
        super(DictEntryArrayWriter, self).__init__(ptr, dbuf)

    def writebodyat(self, newptr):
        for i in xrange(self.count):
            newptr[i].me_hash = self.ptr[i].me_hash
            key = self.ptr[i].me_key
            if key == ffi.NULL or ptrint(key) == DICT_DUMMY:
                # Need to write as a symbol
                newptr[i].me_key = key
                newptr[i].me_value = ffi.NULL
            else:
                # Need to copy "key" and "value"
                keyobj = toobj(key)
                if isinstance(keyobj, str):
                    self.DEBUGSTEP = "visiting key: %s" % keyobj
                else:
                    self.DEBUGSTEP = "visiting key: (id 0x%x)" % id(keyobj)
                cloneptr(newptr[i].fieldptr("me_key"), key)
                value = self.ptr[i].me_value
                cloneptr(newptr[i].fieldptr("me_value"), value)


class PyMemberDefWriter(PtrWriter):
    # Note: not a PyObject.
    TYPENAME = "struct PyMemberDef *"

    def writebodyat(self, newptr):
        assert self.ptr != ffi.NULL
        # padding (int)
        # newptr.fieldptr("type").writeraw(b"\0" * 8)
        newptr.type = self.ptr.type
        newptr.offset = self.ptr.offset
        # padding (int)
        # newptr.fieldptr("flags").writeraw(b"\0" * 8)
        newptr.flags = self.ptr.flags
        cloneptr(newptr["name"], self.ptr.name)
        cloneptr(newptr["doc"], self.ptr.doc)


class PyMethodDefWriter(PtrWriter):
    # Note: not a PyObject.
    TYPENAME = "PyMethodDef *"

    def fields(self):
        assert self.ptr != ffi.NULL
        return [
            ("ml_name", Action.CLONE_PTR),
            ("ml_meth", Action.CLONE_PTR_SHALLOW),
            # padding
            # ("ml_flags", Action.RAW, b"\0" * 8),
            ("ml_flags", Action.COPY),
            ("ml_doc", Action.CLONE_PTR),
        ]


class PyMethodDefWriter(PtrWriter):
    TYPENAME = "PyMethodDef *"

    def writebodyat(self, newptr):
        ptr = self.ptr
        # padding
        # newptr.fieldptr("ml_flags").writeraw(b"\0" * 8)
        newptr.ml_flags = ptr.ml_flags
        cloneptr(newptr.fieldptr("ml_name"), ptr.ml_name)
        cloneptr(newptr.fieldptr("ml_doc"), ptr.ml_doc)
        meth = ptr.ml_meth
        dlinfo = dladdr(meth)
        if dlinfo is None:
            msg = "C function 0x%x is outside libraries" % ptrint(meth)
            msg += "\n(it has name %r and doc %r)" % (
                string(ptr.ml_name),
                string(ptr.ml_doc),
            )
            hint = ptrhint(meth)
            msg += hint
            raise NotImplementedError(msg)
        else:
            # Verify this actually works??
            newptr.ml_meth = ptr.ml_meth


class PyWriter(PtrWriter):
    """Common logic for writing a PyObject"""

    def __init__(self, ptr, dbuf):
        # An explicit TYPENAME is required.
        assert self.TYPENAME is not None
        assert ptrint(ptr) != id(
            dbuf.__dict__
        ), "dangerous to serialize DynamicBuffer state"
        super(PyWriter, self).__init__(ptr, dbuf)

    def objptr(self):
        """Return the "object" type that has common fields like ob_type

        It's usually just self.ptr. Sometimes the "object" type is embedded in
        a larger struct (ex. PyHeapTypeObject).
        """
        return self.ptr

    def size(self, padding=True, typeptr=None):
        # Is it a PyVarObject, or PyObject?
        # There are different ways to test. Make sure they are consistent.
        ptr = self.objptr()
        # Just keep it more alive to avoid potential issues
        ptr.ob_refcnt += 8
        if typeptr is None:
            typeptr = ptr.ob_type
        # See macro _PyObject_SIZE and _PyObject_VAR_SIZE in objimpl.h
        size = typeptr.tp_basicsize
        assert size < 50000, "Something is probably wrong"
        if typeptr.tp_itemsize > 0:
            obsize = getattr(ptr, "ob_size", None)
            if obsize is None:
                # PyObject does not have the field. When tp_itemsize is > 0,
                # This should be treated as PyVarObject.
                assert typeof(ptr) == typeof("PyObject *")
                obsize = cast("PyVarObject *", ptr).ob_size
            # Negative ob_size is used by some types. ex. PyLong uses it to
            # mark the number as negative. Therefore "abs" is needed.
            size += typeptr.tp_itemsize * abs(obsize)
            # For why padding is needed - partially explained in objimpl.h
            # tp_dictoffset in typeobject might be an negative number meaning
            # it's at the end of the struct.
            # Note: We don't really care about alignment because it's not an
            # issue for platforms we care about. However, it needs to be kept
            # ABI compatible with the Python implementation.
            if padding:
                size += SIZEOF_VOID_P - 1
                size &= ~(SIZEOF_VOID_P - 1)
        return size

    def maybewriteheader(self):
        """Write the GC header for objects supporting GC"""
        # See PyType_IS_GC and PyObject_IS_GC macro in objimpl.h -
        # Py_TPFLAGS_HAVE_GC must be set in the type object.
        # Note: It's possible that tp_is_gc says "no gc header" but we still
        # write one. That's okay since it's just wasting some bytes.
        ptr = self.objptr()
        if bool(ptr.ob_type.tp_flags & lib.Py_TPFLAGS_HAVE_GC):
            # Is the object opt-out GC?
            isgc = True
            if ptr.ob_type.tp_is_gc != ffi.NULL:
                if typeof(ptr).kind != "pointer":  # <struct ... &>
                    ptr = addressof(ptr)
                ptr = cast("PyObject *", ptr)
                isgc = ptr.ob_type.tp_is_gc(ptr)
            if not isgc:
                return
            # Write the GC header. The object cannot be GC-ed. Therefore write
            # a fixed header marking it as untracked.
            self.dbuf.writegcheader()

    def fields(self):
        # Common fields for PyObject
        header = [
            # Some structures (ex. PyHeapTypeObject) use nested fields and
            # "ob_refcnt" cannot be directly accessed.
            ("PyObject *", Action.CAST),
            # The object cannot be freed. Just leak it.
            ("ob_refcnt", Action.ASSIGN, 1 << 30),
            # Copy type as-is.
            ("ob_type", Action.CLONE_PTR),
            ("", Action.CASTEND),
        ]
        return header + self.pyfields()

    def pyfields(self):
        raise NotImplementedError("implement this!")

    def humantypename(self):
        return ffi.string(self.objptr().ob_type.tp_name)


class PyIntWriter(PyWriter):
    TYPENAME = "PyIntObject *"

    def pyfields(self):
        return [("ob_ival", Action.COPY)]


class PyBoolWriter(PyIntWriter):
    # TYPENAME = "PyIntObject *" # shared struct with different ob_type

    def write(self):
        raise TypeError("should not serialize PyBool (call writeptrat instead)")


class PyFloatWriter(PyWriter):
    TYPENAME = "PyFloatObject *"

    def pyfields(self):
        return [("ob_fval", Action.COPY)]


class PyComplexWriter(PyWriter):
    TYPENAME = "PyComplexObject *"

    def pyfields(self):
        return [("cval", Action.COPY)]


class PyStringWriter(PyWriter):
    TYPENAME = "PyStringObject *"

    def pyfields(self):
        padsize = self.size(padding=True) - self.size(padding=False)
        # Note: it's possible to have length 1 string here, although they
        # might also be stored in the static characters[] buffer.
        # About "+1": Python appends '\0' to the string buffer. See
        # "op->ob_savl[size] = '\0'" in stringobject.c
        strsize = self.ptr.ob_size + 1
        content = ffi.buffer(self.ptr.ob_sval, strsize)[:] + b"\0" * padsize
        # Note: no concern about ob_sval reallocation in place since the
        # refcount is bigger than 1.
        return [
            ("ob_shash", Action.COPY),
            ("ob_size", Action.COPY),
            ("ob_sstate", Action.ASSIGN, lib.SSTATE_NOT_INTERNED),
            ("ob_sval", Action.RAW, content),
        ]


class PyUnicodeWriter(PyWriter):
    TYPENAME = "PyUnicodeObject *"

    def pyfields(self):
        return [
            ("hash", Action.COPY),
            ("length", Action.COPY),
            (
                "str",
                Action.CLONE_PTR,
                CArrayWriter,
                {"itemtype": "Py_UNICODE", "count": self.ptr.length},
            ),
            ("defenc", Action.CLONE_PTR),
        ]


class PyLongWriter(PyWriter):
    TYPENAME = "PyLongObject *"

    def pyfields(self):
        digittype = "uint32_t"
        count = abs(self.ptr.ob_size)
        padsize = self.size(padding=True) - self.size(padding=False)
        count += padsize / sizeof(digittype)
        return [
            ("ob_size", Action.COPY),
            (
                "ob_digit",
                Action.CLONE_PTR_INPLACE,
                CArrayWriter,
                {"itemtype": digittype, "count": count},
            ),
        ]


class PyTupleWriter(PyWriter):
    TYPENAME = "PyTupleObject *"

    def pyfields(self):
        return [
            ("ob_size", Action.COPY),
            (
                "ob_item",
                Action.CLONE_PTR_INPLACE,
                PyObjectArrayWriter,
                {"count": self.ptr.ob_size},
            ),
        ]


class PyFrameWriter(PyWriter):
    TYPENAME = "PyFrameObject *"

    def pyfields(self):
        raise NotImplementedError("cannot serialize PyFrame")


class PyListWriter(PyWriter):
    TYPENAME = "PyListObject *"

    def pyfields(self):
        n = self.ptr.ob_size
        return [
            ("ob_size", Action.COPY),
            ("allocated", Action.ASSIGN, n),
            ("ob_item", Action.CLONE_PTR_REALLOC, PyObjectArrayWriter, {"count": n}),
        ]


class PySetWriter(PyWriter):
    TYPENAME = "PySetObject *"

    def pyfields(self):
        fields = [
            ("fill", Action.COPY),
            ("used", Action.COPY),
            ("mask", Action.COPY),
            ("hash", Action.COPY),
            ("lookup", Action.CLONE_PTR_SHALLOW),
            # Ignore weakref since the object won't be GC-ed.
            # (therefore no need to notify weakref objects)
            ("weakreflist", Action.ASSIGN, ffi.NULL),
        ]

        usesmalltable = self.ptr.table == self.ptr.smalltable
        if usesmalltable:
            fields += [
                ("table", Action.ASSIGN_FIELD_PTR, "smalltable"),
                (
                    "smalltable",
                    Action.CLONE_PTR_INPLACE,
                    SetEntryArrayWriter,
                    {"count": lib.PySet_MINSIZE},
                ),
            ]
        else:
            # See set_table_resize in setobject.c. The size is mask + 1.
            count = self.ptr.mask + 1
            fields += [
                (
                    "table",
                    Action.CLONE_PTR_REALLOC,
                    SetEntryArrayWriter,
                    {"count": count},
                ),
                ("smalltable", Action.RAW, b"\0" * sizeof(self.ptr, "smalltable")),
            ]

        return fields


class PyDictWriter(PyWriter):
    TYPENAME = "PyDictObject *"

    def pyfields(self):
        fields = [
            ("ma_fill", Action.COPY),
            ("ma_used", Action.COPY),
            ("ma_mask", Action.COPY),
            ("ma_lookup", Action.CLONE_PTR_SHALLOW),
        ]

        usesmalltable = self.ptr.ma_table == self.ptr.ma_smalltable
        if usesmalltable:
            fields += [
                ("ma_table", Action.ASSIGN_FIELD_PTR, "ma_smalltable"),
                (
                    "ma_smalltable",
                    Action.CLONE_PTR_INPLACE,
                    DictEntryArrayWriter,
                    {"count": lib.PyDict_MINSIZE},
                ),
            ]
        else:
            # See dictresize in dictobject.c. The size is mask + 1.
            count = self.ptr.ma_mask + 1
            fields += [
                (
                    "ma_table",
                    Action.CLONE_PTR_REALLOC,
                    DictEntryArrayWriter,
                    {"count": count},
                ),
                (
                    "ma_smalltable",
                    Action.RAW,
                    b"\0" * sizeof(self.ptr, "ma_smalltable"),
                ),
            ]

        return fields


class PyCodeWriter(PyWriter):
    TYPENAME = "PyCodeObject *"

    def pyfields(self):
        return [
            ("co_argcount", Action.COPY),
            ("co_nlocals", Action.COPY),
            ("co_stacksize", Action.COPY),
            ("co_flags", Action.COPY),
            # Fix padding - there are 4 bytes between firstlineno and lnotab.
            # ("co_firstlineno", Action.RAW, b"\0" * 8),
            ("co_firstlineno", Action.COPY),
            ("co_code", Action.CLONE_PTR),
            ("co_consts", Action.CLONE_PTR),
            ("co_names", Action.CLONE_PTR),
            ("co_varnames", Action.CLONE_PTR),
            ("co_freevars", Action.CLONE_PTR),
            ("co_cellvars", Action.CLONE_PTR),
            ("co_filename", Action.CLONE_PTR),
            ("co_name", Action.CLONE_PTR),
            ("co_lnotab", Action.CLONE_PTR),
            # Don't care about weakref or zombieframe
            ("co_weakreflist", Action.ASSIGN, ffi.NULL),
            ("co_zombieframe", Action.ASSIGN, ffi.NULL),
        ]


class PyFunctionWriter(PyWriter):
    TYPENAME = "PyFunctionObject *"

    def pyfields(self):
        return [
            ("func_code", Action.CLONE_PTR),
            # func_globals instantly makes things harder.
            ("func_globals", Action.CLONE_PTR),
            ("func_defaults", Action.CLONE_PTR),
            ("func_closure", Action.CLONE_PTR),
            ("func_doc", Action.CLONE_PTR),
            ("func_name", Action.CLONE_PTR),
            ("func_dict", Action.CLONE_PTR),
            ("func_module", Action.CLONE_PTR),
            # Don't care about weakref
            ("func_weakreflist", Action.ASSIGN, ffi.NULL),
        ]


class PyObjectWriter(PyWriter):
    TYPENAME = "PyObject *"

    # Note: Sometimes this writes PyHeapTypeObject. For example, when the
    # ob_type is ABCMeta.

    # Minimal PyObject, plus dictobject and weaklist pointers
    COMMON_SIZE = sizeof("PyObject") + 2 * SIZEOF_VOID_P

    def __init__(self, *args, **kwargs):
        super(PyObjectWriter, self).__init__(*args, **kwargs)
        self._baseinfo = None

    def pyfields(self):
        # This is a bit complicated because the struct "PyObject" itself is
        # not really useful. The actual fields of the object is specified
        # by its type (ob_type) object. For example, the "tp_dictoffset"
        # field decides the location of a "__dict__" in the object struct.
        #
        # For common objects (i.e. pure Python objects). Their size is
        # sizeof('PyObject') + sizeof('PyObject*') * 2. The two pointers are
        # used for a "__dict__", and "__weakref__".  They are after the
        # PyObject struct body. Read type_new in typeobject.c for the context.
        #
        # Another common type is "Struct Sequence Objects", created by
        # PyStructSequence_InitType (in structseq.c). It is the C equivalent of
        # namedtuple.  It sets the tp_members list and maintains tp_basicsize.
        # The tp_members list contains offsets to "PyObject*"s. So we just
        # clone them.
        #
        # the next difficult thing is what if a native type (ex. bytes) is
        # subclassed? In that case the native writer should be reused.
        typeptr = self.ptr.ob_type
        fields = []

        baseptr, basesize, writer = self.baseinfo()
        if writer is not None:
            fields += (
                [(writer.typename, Action.CAST)]
                + writer.pyfields()
                + [("", Action.CASTEND)]
            )
            # Also populate self._offsettable
            self.mergeoffsettable(writer.offsettable().items())
        else:
            # No predefined writer found. But using the existing
            # information like tp_dictoffset, tp_members, we might still
            # be able to serialize the object. Practically, this handles
            # types created by PyStructSequence_InitType.
            #
            # Maybe this can be a warning if it's not too noisy.
            pass

        # Eveything within 0..basesize range is written so we shouldn't
        # write them again.

        # Track written object offsets
        offsets = set()

        # Write weakreflist (NULL)
        weakoffset = typeptr.tp_weaklistoffset
        if weakoffset != 0 and weakoffset not in offsets and weakoffset >= basesize:
            self.mergeoffsettable([(weakoffset, "__weakref__")])
            offsets.add(weakoffset)
            fields += [((weakoffset, "PyObject *"), Action.ASSIGN, ffi.NULL)]

        # Write dict
        dictoffset = self.dictoffset()
        if dictoffset and dictoffset not in offsets and dictoffset >= basesize:
            offsets.add(dictoffset)
            fields += [((dictoffset, "PyObject *"), Action.CLONE_PTR)]

        # Write members (but not weakref or dict)
        memberfields = self.memberfields()
        for memberfield in memberfields:
            offset = memberfield[0][0]
            if offset not in offsets and offset >= basesize:
                offsets.add(offset)
                fields.append(memberfield)

        # For PyVarObject, also need to copy ob_size.
        # There is no obvious way to detect whether it's PyVarObject.
        # So let's check if the "ob_size" offset has been take or not.
        # Note: tp_itemsize might be 0 - it's not an accurate indicator.
        sizeoffset = offsetof("PyVarObject", "ob_size")
        if basesize == 0 and sizeoffset not in offsets and memberfields:
            # It might be a PyStructSequence instance.
            self.mergeoffsettable([(sizeoffset, "ob_size")])
            fields += [
                ("PyVarObject *", Action.CAST),
                ("ob_size", Action.COPY),
                ("", Action.CASTEND),
            ]

        # The ensureinitialized check will capture bytes missed here.
        # Therefore if it runs, every field of a struct should be written.
        return fields

    def maybewritefooter(self):
        basetypeptr, basesize, writer = self.baseinfo()
        # XXX: Perhaps there are better ways doing this?
        # This might mess up if there are nested footers.
        # Although it's only used by PyHeapTypeObject for now.
        if writer:
            writer.maybewritefooter()

    def postwritefixup(self, newptr):
        basetypeptr, basesize, writer = self.baseinfo()
        # Only used by PyHeapTypeObject for now.
        # Why PyObjectWriter is used for HeapType?
        if writer:
            writer.postwritefixup(newptr)

    def baseinfo(self):
        """Return (basetypeptr, basesize, writer?)

        The base type is the native type that mostly defines the native struct size.
        """
        if self._baseinfo is not None:
            # cached
            return self._baseinfo

        # Find the native (non-heap) base type. Note: A native type is usually
        # defined using a static "PyTypeObject". That is not allocated in heap.
        # Use HEAPTYPE as an approximate to find out native base class.
        baseptr = self.ptr.ob_type
        while baseptr != ffi.NULL and baseptr.tp_flags & lib.Py_TPFLAGS_HEAPTYPE:
            baseptr = baseptr.tp_base

        # Is the base type a well-known native type?
        # If so, we should use the dedicated writer to write part of it.
        writertype = TYPEID_WRITE_MAP.get(ptrint(baseptr))
        if not writertype or writertype is PyObjectWriter:
            # Also look at TYPENAME_WRITER_MAP
            tpname = ffi.string(baseptr.tp_name)

            writertype2 = TYPENAME_WRITER_MAP.get(tpname)
            if writertype2:
                writertype = writertype2
            # else:
            #  if tpname == 'CFunctionType':
            #      import ipdb; ipdb.set_trace()
            #  if tpname.startswith('_ctypes'):
            #      import ipdb; ipdb.set_trace()

        # _ctypes uses metatypes. It uses PyType_Type.tp_new to create new
        # types that need serialization. That means the tp_name we got from
        # here can be arbitrary defined in the Python world. So a
        # TYPEID_WRITE_MAP won't handle them.
        #
        # To give an example, ctypes.py defines CFunctionType(_ctypes.CFuncPtr)
        # That "CFunctionType" thing defined in ".py" has ob_type->tp_name set
        # to "CFunctionType", which is defined by ".py". Its
        # ob_type->tp_base->tp_name is "_ctypes.PyCFuncPtr", defined by
        # _ctypes.c.
        if not writertype and baseptr.tp_base != ffi.NULL:
            tpmetaname = ffi.string(baseptr.tp_base.tp_name)

        basesize = 0
        writer = None
        if writertype:
            if isinstance(writertype, str):
                raise NotImplementedError(writertype)
            writer = writertype(self.ptr, self.dbuf)
            basesize = writer.size(typeptr=baseptr)

        self._baseinfo = (baseptr, basesize, writer)
        return self._baseinfo

    def memberfields(self):
        """Return an array of fields specified in 'tp_members'"""
        # Read tp_members. A typical use is by PyStructSequence_InitType
        fields = []
        typeptr = self.ptr.ob_type
        if typeptr.tp_members != ffi.NULL:
            i = 0
            while True:
                # PyMemberDef
                member = typeptr.tp_members[i]
                offset = member.offset
                if member.name == ffi.NULL:
                    break
                if member.type in {lib.T_OBJECT, lib.T_OBJECT_EX}:
                    # Used by PyStructSequence_InitType
                    fields += [((offset, "PyObject *"), Action.CLONE_PTR)]
                elif member.type == lib.T_PYSSIZET:
                    fields += [((offset, "ssize_t"), Action.COPY)]
                else:
                    raise NotImplementedError(
                        "member type %s (check T_* constants in structmember.h)"
                        % member.type
                    )
                desc = "member %s" % ffi.string(member.name)
                self.mergeoffsettable([(member.offset, desc)])
                i += 1
        return fields

    def dictoffset(self):
        """Return PyObject* offsets for __dict__"""
        dictptr = lib._PyObject_GetDictPtr(self.ptr)
        if dictptr == ffi.NULL:
            return None
        dictoffset = ptrint(dictptr) - ptrint(self.ptr)
        # Sanity check: compare it with our understanding about "dictoffset"
        dictoffset2 = self.ptr.ob_type.tp_dictoffset
        if dictoffset2 < 0:
            dictoffset2 += self.size()
        assert dictoffset2 == dictoffset
        self.mergeoffsettable([(dictoffset, "__dict__")])
        return dictoffset

    def offsettable(self):
        return self.mergeoffsettable(super(PyObjectWriter, self).offsettable().items())


class PyTypeWriter(PyWriter):
    # This is rarely used directly. It exists for clarification.
    # Check PyHeapTypeWriter instead.
    TYPENAME = "PyTypeObject *"

    def pyfields(self, isheaptype=False):
        # If isheaptype is True, some fields are skipped.
        # Only used by PyHeapTypeWriter.
        ptr = self.objptr()
        isheaptype2 = bool(ptr.tp_flags & lib.Py_TPFLAGS_HEAPTYPE)
        assert (
            isheaptype2 == isheaptype
        ), "Seems PyHeapTypeWriter should be used instead"

        flags = self.ptr.tp_flags
        # Drop Py_TPFLAGS_VALID_VERSION_TAG. It needs to be re-assigned.
        # See typeobject.c - assign_version_tag.
        if flags & lib.Py_TPFLAGS_VALID_VERSION_TAG:
            flags ^= lib.Py_TPFLAGS_VALID_VERSION_TAG

        fields = [
            ("ob_size", Action.COPY),
            ("tp_name", Action.CLONE_PTR),
            ("tp_basicsize", Action.COPY),
            ("tp_itemsize", Action.COPY),
            ("tp_dealloc", Action.CLONE_PTR_SHALLOW),
            ("tp_print", Action.CLONE_PTR_SHALLOW),
            ("tp_getattr", Action.CLONE_PTR_SHALLOW),
            ("tp_setattr", Action.CLONE_PTR_SHALLOW),
            ("tp_compare", Action.CLONE_PTR_SHALLOW),
            ("tp_repr", Action.CLONE_PTR_SHALLOW),
            ("tp_hash", Action.CLONE_PTR_SHALLOW),
            ("tp_call", Action.CLONE_PTR_SHALLOW),
            ("tp_str", Action.CLONE_PTR_SHALLOW),
            ("tp_getattro", Action.CLONE_PTR_SHALLOW),
            ("tp_setattro", Action.CLONE_PTR_SHALLOW),
            ("tp_flags", Action.ASSIGN, flags),
            ("tp_doc", Action.CLONE_PTR),
            ("tp_traverse", Action.CLONE_PTR_SHALLOW),
            ("tp_clear", Action.CLONE_PTR_SHALLOW),
            ("tp_richcompare", Action.CLONE_PTR_SHALLOW),
            ("tp_weaklistoffset", Action.COPY),
            ("tp_iter", Action.CLONE_PTR_SHALLOW),
            ("tp_iternext", Action.CLONE_PTR_SHALLOW),
            ("tp_methods", Action.CLONE_PTR_SHALLOW),
            ("tp_getset", Action.CLONE_PTR_SHALLOW),
            ("tp_base", Action.CLONE_PTR),
            ("tp_dict", Action.CLONE_PTR),
            ("tp_descr_get", Action.CLONE_PTR_SHALLOW),
            ("tp_descr_set", Action.CLONE_PTR_SHALLOW),
            ("tp_dictoffset", Action.COPY),
            ("tp_init", Action.CLONE_PTR_SHALLOW),
            ("tp_alloc", Action.CLONE_PTR_SHALLOW),
            ("tp_new", Action.CLONE_PTR_SHALLOW),
            ("tp_free", Action.CLONE_PTR_SHALLOW),
            ("tp_is_gc", Action.CLONE_PTR_SHALLOW),
            ("tp_bases", Action.CLONE_PTR),
            ("tp_mro", Action.CLONE_PTR),
            ("tp_cache", Action.CLONE_PTR_SHALLOW),
            ("tp_subclasses", Action.CLONE_PTR),
            ("tp_weaklist", Action.ASSIGN, ffi.NULL),
            ("tp_del", Action.CLONE_PTR_SHALLOW),
            # Fix padding gap between tp_version_tag (unsigned int) and nb_add.
            # tp_version_tag needs to be reassigned from Python. See
            # typeobject.c, next_version_tag.
            # ("tp_version_tag", Action.RAW, b"\0" * 8),
            ("tp_version_tag", Action.ASSIGN, 0),
        ]

        if not isheaptype:
            # HeapType handles these fields differently.
            fields += [
                ("tp_as_number", Action.CLONE_PTR_SHALLOW),
                ("tp_as_sequence", Action.CLONE_PTR_SHALLOW),
                ("tp_as_mapping", Action.CLONE_PTR_SHALLOW),
                ("tp_as_buffer", Action.CLONE_PTR_SHALLOW),
                ("tp_members", Action.CLONE_PTR_SHALLOW),
            ]

        return fields


class PyHeapTypeWriter(PyWriter):
    # This is one of the most complicated types.

    # Note Doc/includes/typestruct.h is outdated (ex. missed tp_del and
    # tp_version_tag). Check Include/object.h for the right definition.

    # There are two types PyTypeObject, PyHeapTypeObject. The latter is the
    # actual type object used widely (ex. PyType_Type.tp_basicsize is
    # sizeof(PyHeapTypeObject)). PyHeapTypeObject defines PyTypeObject as its
    # first field instead of expanding the fields in-place (using macros like
    # PyObject_HEAD). That makes fields like "ob_size" inaccessible directly.
    # Therefore use PyTypeObject for most of the time and cast into
    # PyHeapTypeObject when writing PyHeapTypeObject fields.
    TYPENAME = "PyHeapTypeObject *"

    def objptr(self):
        return addressof(self.ptr.ht_type)

    def maybewritefooter(self):
        # See PyType_GenericAlloc in typeobject.c. An extra item (not counted
        # in ob_size) is added and zeroed out so tp_members (which is past the
        # main object, see PyHeapType_GET_MEMBERS) would behave sane.
        # Otherwise tp_members might access invalid memory.
        size = self.objptr().ob_type.tp_itemsize  # ob_type: the "type" type
        self.dbuf.extendraw(b"\0" * size, initialized=True)

    def postwritefixup(self, newptr):
        # Fixup subclass potentially.
        # More convinent to just use Python object here.
        obj = toobj(self.objptr())
        for base in obj.__bases__:
            if id(base) in self.dbuf.ptrmap:
                # The base object was serialized
                continue
            else:
                # The base object's subclasses needs fixed up
                baseptr = cast("PyObject *", id(base))
                self.dbuf.addsubclassfixup(newptr, baseptr)

    def pyfields(self):
        ptr = self.objptr()
        if not (ptr.tp_flags & lib.Py_TPFLAGS_HEAPTYPE):
            humanname = ffi.string(ptr.tp_name)
            # XXX: Should we try serialize non-heap types?
            raise NotImplementedError("%r is not a heap type" % humanname)

        tpwriter = PyTypeWriter(self.ptr, self.dbuf)
        fields = (
            [(PyTypeWriter.TYPENAME, Action.CAST)]
            + tpwriter.pyfields(isheaptype=True)
            + [("", Action.CASTEND)]
            + [
                ("as_number.nb_add", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_subtract", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_multiply", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_divide", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_remainder", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_divmod", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_power", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_negative", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_positive", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_absolute", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_nonzero", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_invert", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_lshift", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_rshift", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_and", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_xor", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_or", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_coerce", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_int", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_long", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_float", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_oct", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_hex", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_add", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_subtract", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_multiply", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_divide", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_remainder", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_power", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_lshift", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_rshift", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_and", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_xor", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_or", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_floor_divide", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_true_divide", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_floor_divide", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_inplace_true_divide", Action.CLONE_PTR_SHALLOW),
                ("as_number.nb_index", Action.CLONE_PTR_SHALLOW),
                ("as_mapping.mp_length", Action.CLONE_PTR_SHALLOW),
                ("as_mapping.mp_subscript", Action.CLONE_PTR_SHALLOW),
                ("as_mapping.mp_ass_subscript", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_length", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_concat", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_repeat", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_item", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_slice", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_ass_item", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_ass_slice", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_contains", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_inplace_concat", Action.CLONE_PTR_SHALLOW),
                ("as_sequence.sq_inplace_repeat", Action.CLONE_PTR_SHALLOW),
                ("as_buffer.bf_getreadbuffer", Action.CLONE_PTR_SHALLOW),
                ("as_buffer.bf_getwritebuffer", Action.CLONE_PTR_SHALLOW),
                ("as_buffer.bf_getsegcount", Action.CLONE_PTR_SHALLOW),
                ("as_buffer.bf_getcharbuffer", Action.CLONE_PTR_SHALLOW),
                ("as_buffer.bf_getbuffer", Action.CLONE_PTR_SHALLOW),
                ("as_buffer.bf_releasebuffer", Action.CLONE_PTR_SHALLOW),
                ("ht_name", Action.CLONE_PTR),
                ("ht_slots", Action.CLONE_PTR),
            ]
        )

        # tp_as_number, tp_as_sequence, ... might just point to as_number, ...
        # in a same struct. Detect that.
        for asname in ["as_number", "as_sequence", "as_mapping", "as_buffer"]:
            tpptr = getattr(self.ptr.ht_type, "tp_%s" % asname)
            htptr = getattr(self.ptr, asname)
            name = "ht_type.tp_%s" % asname
            if tpptr == htptr:
                fields.append((name, Action.ASSIGN_FIELD_PTR, asname))
            else:
                # Hopefully this is a pointer inside libraries
                fields.append((name, Action.CLONE_PTR_SHALLOW))

        # tp_members usually points to just after the end of the struct (!!!)
        # typeobject.c:
        #   type->tp_members = PyHeapType_GET_MEMBERS(et);
        # object.h:
        #   #define PyHeapType_GET_MEMBERS(etype) \
        #   ((PyMemberDef *)(((char *)etype) + Py_TYPE(etype)->tp_basicsize))
        #
        # Detect and emulate the behavior
        basicsize = ptr.ob_type.tp_basicsize
        assert basicsize == sizeof("PyHeapTypeObject")
        if ptrint(ptr.tp_members) - ptrint(self.ptr) == basicsize:
            fields.append(("ht_type.tp_members", Action.ASSIGN_OFFSET_PTR, basicsize))
        else:
            raise NotImplementedError("unexpected tp_members - bug in python?")

        # After the end of the type object, there is a list of PyMemberDef
        # called "slots". Check traverse_slots in typeobject.c for details.
        for i in xrange(ptr.ob_size):
            # See PyHeapType_GET_MEMBERS for how offset is calculated
            offset = ptr.ob_type.tp_basicsize + i * ptr.ob_type.tp_itemsize
            assert ptr.ob_type.tp_itemsize == sizeof("PyMemberDef")
            slotname = ffi.string(cast("PyMemberDef *", ptrint(self.ptr) + offset).name)
            self.mergeoffsettable([(offset, "slots['%s']" % (slotname,))])
            fields += [
                # Note: It's not "PyMemberDef *" but an embedded struct!
                ((offset, "PyMemberDef"), Action.CLONE_PTR_INPLACE, PyMemberDefWriter)
            ]
        return fields


class PyGetSetDescrWriter(PyWriter):
    TYPENAME = "PyGetSetDescrObject *"

    def pyfields(self):
        return [
            ("d_type", Action.CLONE_PTR),
            ("d_name", Action.CLONE_PTR),
            ("d_getset", Action.CLONE_PTR_SHALLOW),
        ]


class PyMemberDescrWriter(PyWriter):
    TYPENAME = "PyMemberDescrObject *"

    def pyfields(self):
        return [
            ("d_type", Action.CLONE_PTR),
            ("d_name", Action.CLONE_PTR),
            ("d_member", Action.CLONE_PTR, PyMemberDefWriter),
        ]


class PyMethodDescrWriter(PyWriter):
    TYPENAME = "PyMethodDescrObject *"

    def pyfields(self):
        return [
            ("d_type", Action.CLONE_PTR),
            ("d_name", Action.CLONE_PTR),
            ("d_method", Action.CLONE_PTR, PyMethodDefWriter),
        ]


class PyWrapperDescrWriter(PyWriter):
    TYPENAME = "PyWrapperDescrObject *"

    def pyfields(self):
        return [
            ("d_type", Action.CLONE_PTR),
            ("d_name", Action.CLONE_PTR),
            ("d_base", Action.CLONE_PTR_SHALLOW),
            # void * (!!)
            ("d_wrapped", Action.CLONE_PTR_SHALLOW),
        ]


class PyWeakReferenceWriter(PyWriter):
    TYPENAME = "PyWeakReference *"

    def writebodyat(self, newptr):
        super(PyWeakReferenceWriter, self).writebodyat(newptr)
        self.DEFERREDWRITES.append(lambda: self.writefixup(newptr))

    def writefixup(self, newptr):
        # Need to revert the "symbol" offset adjustment (assuming None
        # is referred as a symbol).
        newfieldptr = newptr.fieldptr("wr_object")
        self.dbuf.writeweakrefptr(newfieldptr, self.ptr.wr_object)

    def pyfields(self):
        # By default, write None as "wr_object" so we won't serializing too
        # many "uninteresting" objects. tp_subclasses is a list of weakrefs.
        # And subclasses can introduce objects way more than requested.
        #
        # However, correctness is also important. So we add a postwrite
        # function to fixup the object pointer after other objects have been
        # written. Then check if the object is serialized and write it if so.
        return [
            # NULL is illegal for PyWeakReference. But it will be fixed up by
            # writefixup.
            ("wr_object", Action.ASSIGN, ffi.NULL),
            ("wr_callback", Action.CLONE_PTR),
            ("hash", Action.COPY),
            # The linked list is used to set a chain of weakrefs' wr_object to
            # None.  Since neither the object serialized (wr_object) nor this
            # weakref object will be GC-ed, just don't care about it.
            ("wr_prev", Action.ASSIGN, ffi.NULL),
            ("wr_next", Action.ASSIGN, ffi.NULL),
        ]


class PyCFunctionWriter(PyWriter):
    # In methodobject.h
    TYPENAME = "PyCFunctionObject *"

    def pyfields(self):
        return [
            ("m_ml", Action.CLONE_PTR, PyMethodDefWriter, None),
            ("m_self", Action.CLONE_PTR),
            ("m_module", Action.CLONE_PTR),
        ]


class PyCapsuleWriter(PyWriter):
    # In capsule.c. Used by some native modules (ex. _socket.CAPI)
    TYPENAME = "PyCapsule *"

    def pyfields(self):
        # Make sure all "void *" pointers can be resolved early.
        # This shows friendly error message.
        for name in ["pointer", "context", "destructor"]:
            value = getattr(self.ptr, name)
            if value != ffi.NULL and not self.dbuf.hasptr(value):
                raise NotImplementedError(
                    "Cannot serialize %r: field %s points to an unknown address"
                    % (toobj(self.ptr), name)
                )

        return [
            ("pointer", Action.COPY),
            ("name", Action.CLONE_PTR),
            ("context", Action.COPY),
            ("destructor", Action.COPY),
        ]


class PyClassWriter(PyWriter):
    # old-style class, in classobject.h
    TYPENAME = "PyClassObject *"

    def pyfields(self):
        return [
            ("cl_bases", Action.CLONE_PTR),
            ("cl_dict", Action.CLONE_PTR),
            ("cl_name", Action.CLONE_PTR),
            ("cl_getattr", Action.CLONE_PTR),
            ("cl_setattr", Action.CLONE_PTR),
            ("cl_delattr", Action.CLONE_PTR),
            ("cl_weakreflist", Action.ASSIGN, ffi.NULL),
        ]


class PyInstanceWriter(PyWriter):
    # in classobject.h
    TYPENAME = "PyInstanceObject *"

    def pyfields(self):
        return [
            ("in_class", Action.CLONE_PTR),
            ("in_dict", Action.CLONE_PTR),
            ("in_weakreflist", Action.ASSIGN, ffi.NULL),
        ]


class PyMethodWriter(PyWriter):
    # in classobject.h
    TYPENAME = "PyMethodObject *"

    def pyfields(self):
        return [
            ("im_func", Action.CLONE_PTR),
            ("im_self", Action.CLONE_PTR),
            ("im_class", Action.CLONE_PTR),
            ("im_weakreflist", Action.ASSIGN, ffi.NULL),
        ]


class PyClassMethodWriter(PyWriter):
    # in funcobject.c
    TYPENAME = "classmethod *"

    def pyfields(self):
        return [("cm_callable", Action.CLONE_PTR)]


class PyPropertyWriter(PyWriter):
    # in descrobject.c
    TYPENAME = "propertyobject *"

    def pyfields(self):
        pad = b"\0" * (self.size() - offsetof(self.TYPENAME, "getter_doc"))
        return [
            ("prop_get", Action.CLONE_PTR),
            ("prop_set", Action.CLONE_PTR),
            ("prop_del", Action.CLONE_PTR),
            ("prop_doc", Action.CLONE_PTR),
            ("getter_doc", Action.RAW, pad),
            ("getter_doc", Action.COPY),
        ]


class PyCellWriter(PyWriter):
    TYPENAME = "PyCellObject *"

    def pyfields(self):
        return [("ob_ref", Action.CLONE_PTR)]


class PyModuleWriter(PyWriter):
    TYPENAME = "PyModuleObject *"

    # Most native modules are not safe to serialize since their init functions
    # will be bypassed and some side effects cannot be re-done. Typically, side
    # effect like changing global variables or anything outside the module dict
    # means the module cannot be safely serialized:
    #
    #   initmod() {
    #     global_var = ...        // BAD
    #     some_var.foobar = ...   // BAD
    #     m = Py_InitModule("mod", methods);  // GOOD
    #     PyModule_AddIntConstant(m, x, y);   // GOOD
    #     PyType_Ready(&MyType);  // GOOD if the type is exposed
    #     MyType.tp_base = ...;   // BAD !
    #     MyError = PyErr_NewException(...) // BAD if MyError is global
    #   }
    #
    # PyType_Ready is an exception, its side-effect will be replayed, if the
    # type can be found from the module dict. So if a type is statically
    # defined (i.e. all fields are assigned statically), and exposed via
    # module dict, then it can be serialized.
    #
    # Below is a list of modules that are safe to serialize.
    #
    # UPDATED: To make it simpler, just don't have a whitelist.
    #
    WHITELIST = set(
        (
            "_bisect.so _functools.so _heapq.so _locale.so _random.so bz2.so "
            "crypt.so fcntl.so math.so operator.so strop.so syslog.so"
        ).split()
    )

    # Used to print debug messages
    indent = 0

    def writebodyat(self, newptr):
        result = super(PyModuleWriter, self).writebodyat(newptr)
        self.dbuf.markmodule(newptr)
        return result

    def writeptrat(self, offset, **kwargs):
        assert self.ptr != ffi.NULL
        existed = self.existed()
        mod = toobj(self.ptr)
        path = getattr(mod, "__file__", "") or ""
        isnative = ".py" not in path[-4:].lower()
        needautofix = False
        if not existed:
            if isnative:
                # Try this whitelist?
                if os.path.basename(path) not in self.WHITELIST:
                    needautofix = True
        # Insert a "eval" that imports the module
        if needautofix:
            name = getattr(mod, "__name__", None)
            if name:
                sys.stderr.write("   AUTOFIX module %r - added to eval list\n" % name)
                if path:
                    code = "importnative(%r, %r)" % (name, path)
                else:
                    code = "imp.init_builtin(%r)" % name
                self.dbuf.appendevalcode(code, mod)
                existed = True
            else:
                raise NotImplementedError(
                    "native module %r is probably unsafe to serialize" % mod
                )
        if existed:
            offset.writeptr(self.ptr, **kwargs)
        else:
            # Friendly message about which module is being serialized
            msg = "%sserializing %r" % (" " * PyModuleWriter.indent, mod)
            if isnative:
                msg += " (native)"
            sys.stderr.write(">> %s started\n" % msg)
            PyModuleWriter.indent += 1
            offset.writeptr(self.write(), **kwargs)
            PyModuleWriter.indent -= 1
            sys.stderr.write("<< %s ended\n" % msg)

    def pyfields(self):
        return [("md_dict", Action.CLONE_PTR)]


class PatternObjectWriter(PyWriter):
    # _sre.SRE_Pattern
    TYPENAME = "PatternObject *"

    def pyfields(self):
        # size with padding considered
        codesize = self.size() - offsetof("PatternObject", "code")
        code = ffi.buffer(self.ptr.code, codesize)[:]
        return [
            ("ob_size", Action.COPY),
            ("groups", Action.COPY),
            ("groupindex", Action.CLONE_PTR),
            ("indexgroup", Action.CLONE_PTR),
            ("pattern", Action.CLONE_PTR),
            # padding
            # ("flags", Action.RAW, b"\0" * 8),
            ("flags", Action.COPY),
            ("weakreflist", Action.ASSIGN, ffi.NULL),
            ("codesize", Action.COPY),
            ("code", Action.RAW, code),
        ]


class PyRawCopyWriter(PyWriter):
    """Byte-to-byte copy of PyObject"""

    FIRSTFIELD = None

    def pyfields(self):
        firstfield = self.FIRSTFIELD
        assert firstfield
        size = self.size() - offsetof(self.TYPENAME, firstfield)
        content = ffi.buffer(addressof(self.ptr, firstfield), size)[:]
        return [(firstfield, Action.RAW, content)]


class DatetimeDateWriter(PyRawCopyWriter):
    TYPENAME = "PyDateTime_Date *"
    FIRSTFIELD = "hashcode"


class RandomObjectWriter(PyRawCopyWriter):
    TYPENAME = "RandomObject *"
    FIRSTFIELD = "state"


class ThreadLockWriter(PyWriter):
    TYPENAME = "lockobject *"

    def pyfields(self):
        return [
            ("lock_lock", Action.CLONE_LOCK),
            ("in_weakreflist", Action.ASSIGN, ffi.NULL),
        ]


# _struct
#
class StructFormatDefWriter(PtrWriter):
    TYPENAME = "formatdef *"

    def fields(self):
        return [
            # padding
            # ("format", Action.RAW, b"\0" * 8),
            ("format", Action.COPY),
            ("size", Action.COPY),
            ("alignment", Action.COPY),
            ("unpack", Action.CLONE_PTR_SHALLOW),
            ("pack", Action.CLONE_PTR_SHALLOW),
        ]


class StructFormatCodeWriter(PtrWriter):
    # Not a PyObject
    TYPENAME = "formatcode *"

    def fields(self):
        return [
            ("fmtdef", Action.CLONE_PTR, StructFormatDefWriter),
            ("offset", Action.COPY),
            ("size", Action.COPY),
        ]


class StructFormatCodeArrayWriter(NullTerminatedArrayWriter):
    # Write formatcode[]
    ITEMTYPE = "formatcode"
    CLONEARGS = {"wtype": StructFormatCodeWriter}


class StructWriter(PyWriter):
    TYPENAME = "PyStructObject *"

    def pyfields(self):
        return [
            ("s_size", Action.COPY),
            ("s_len", Action.COPY),
            ("s_codes", Action.CLONE_PTR, StructFormatCodeArrayWriter),
            ("s_format", Action.CLONE_PTR),
            ("weakreflist", Action.ASSIGN, ffi.NULL),
        ]


class UnicodeUCDWriter(PyWriter):
    # Not a good struct name. But the library uses it...
    TYPENAME = "PreviousDBVersion *"

    def pyfields(self):
        return [
            ("name", Action.CLONE_PTR),
            ("getrecord", Action.CLONE_PTR_SHALLOW),
            ("normalization", Action.CLONE_PTR_SHALLOW),
        ]


class FFITypeWriter(PtrWriter):
    TYPENAME = "ffi_type *"

    def fields(self):
        if self.ptr.elements != ffi.NULL:
            raise NotImplementedError(
                "Don't know how to copy ffi_type with non-NULL elements"
            )
        return [
            ("size", Action.COPY),
            # alignment
            ("alignment", Action.RAW, b"\0" * 8),
            ("alignment", Action.COPY),
            ("type", Action.COPY),
            ("elements", Action.ASSIGN, ffi.NULL),
        ]


class CTypesStgDictWriter(PyWriter):
    TYPENAME = "StgDictObject *"

    def objptr(self):
        return cast("PyDictObject *", self.ptr)

    def pyfields(self):
        if self.ptr.shape != ffi.NULL:
            raise NotImplementedError("Don't know how to copy shape from StgDict yet")
        # Cannot use CLONE_PTR_INPLACE for the first field (dict) because that
        # will fail ptrmap duplication check. Therefore, inline the fields.
        assert offsetof(self.TYPENAME, "dict") == 0
        dictwriter = PyDictWriter(self.ptr, self.dbuf)
        fields = (
            [(dictwriter.TYPENAME, Action.CAST)]
            + dictwriter.pyfields()
            + [("", Action.CASTEND)]
            + [
                ("size", Action.COPY),
                ("align", Action.COPY),
                ("length", Action.COPY),
                ("ffi_type_pointer", Action.CLONE_PTR_INPLACE, FFITypeWriter),
                ("proto", Action.CLONE_PTR),
                ("setfunc", Action.CLONE_PTR_SHALLOW),
                ("getfunc", Action.CLONE_PTR_SHALLOW),
                ("paramfunc", Action.CLONE_PTR_SHALLOW),
                ("argtypes", Action.CLONE_PTR),
                ("converters", Action.CLONE_PTR),
                ("restype", Action.CLONE_PTR),
                ("checker", Action.CLONE_PTR),
                # padding
                # ("flags", Action.RAW, b"\0" * 8),
                ("flags", Action.COPY),
                ("format", Action.CLONE_PTR),
                # padding
                ("ndim", Action.RAW, b"\0" * 8),
                ("ndim", Action.COPY),
                ("shape", Action.ASSIGN, ffi.NULL),
            ]
        )
        return fields


class CythonFunctionWriter(PyWriter):
    TYPENAME = "__pyx_CyFunctionObject *"

    def objptr(self):
        return cast("PyCFunctionObject *", self.ptr)

    def pyfields(self):
        if self.ptr.defaults != ffi.NULL:
            raise NotImplementedError("defaults of CythonFunction needs to be NULL")
        # Cannot use CLONE_PTR_INPLACE for the first field (func) because that
        # will fail ptrmap duplication check. Therefore, inline the fields.
        assert offsetof(self.TYPENAME, "func") == 0
        funcwriter = PyCFunctionWriter(self.ptr, self.dbuf)
        fields = (
            [(funcwriter.TYPENAME, Action.CAST)]
            + funcwriter.pyfields()
            + [
                ("", Action.CASTEND),
                ("func_weakreflist", Action.ASSIGN, ffi.NULL),
                ("func_dict", Action.CLONE_PTR),
                ("func_name", Action.CLONE_PTR),
                ("func_qualname", Action.CLONE_PTR),
                ("func_doc", Action.CLONE_PTR),
                ("func_globals", Action.CLONE_PTR),
                ("func_code", Action.CLONE_PTR),
                ("func_closure", Action.CLONE_PTR),
                ("func_classobj", Action.CLONE_PTR),
                ("defaults", Action.CLONE_PTR_SHALLOW),
                ("defaults_pyobjects", Action.COPY),
                ("flags", Action.COPY),
                ("defaults_tuple", Action.CLONE_PTR),
                ("defaults_kwdict", Action.CLONE_PTR),
                ("defaults_getter", Action.CLONE_PTR_SHALLOW),
                ("func_annotations", Action.CLONE_PTR),
            ]
        )
        return fields


# Meta-programming: Generate a "writer" using its C struct
# Requires tp_name to be a fixed name.


def generatewriter(structname):
    """Generate a writer for handling a simple type.

    A type is simple if all of its fields are like "PyObject *", "Py_ssize_t",
    etc.

    structname is the C struct name for the instance objects.
    """
    fieldactions = []
    for fieldname, cfield in typeof(structname).fields:
        if fieldname in ["ob_refcnt", "ob_type"]:
            # Handled by "fields"
            continue
        fieldtype = cfield.type
        if fieldtype == typeof("ssize_t"):
            fieldactions.append((fieldname, Action.COPY))
        elif fieldtype == typeof("PyObject *"):
            fieldactions.append((fieldname, Action.CLONE_PTR))
        else:
            raise NotImplementedError("not implemented type: %r" % fieldtype)

    class GeneratedPyWriter(PyWriter):
        TYPENAME = "%s *" % structname

        def pyfields(self):
            return fieldactions

    return GeneratedPyWriter


TYPEID_WRITE_MAP = {
    # PyBaseObject_Type is the "object" type. No special handling needed.
    # addrint(lib.PyBaseObject_Type): PyBaseObjectWriter,
    # addrint(lib.PyBaseString_Type): "PyBaseStringWriter",
    addrint(lib.PyBool_Type): PyBoolWriter,
    addrint(lib.PyBuffer_Type): "PyBufferWriter",
    addrint(lib.PyByteArrayIter_Type): "PyByteArrayIterWriter",
    addrint(lib.PyByteArray_Type): "PyByteArrayWriter",
    addrint(lib.PyCFunction_Type): PyCFunctionWriter,
    addrint(lib.PyCObject_Type): "PyCObjectWriter",
    addrint(lib.PyCallIter_Type): "PyCallIterWriter",
    addrint(lib.PyCapsule_Type): PyCapsuleWriter,
    addrint(lib.PyCell_Type): PyCellWriter,
    addrint(lib.PyClassMethod_Type): generatewriter("classmethod"),
    addrint(lib.PyClass_Type): PyClassWriter,
    addrint(lib.PyCode_Type): PyCodeWriter,
    addrint(lib.PyComplex_Type): PyComplexWriter,
    addrint(lib.PyDictItems_Type): "PyDictItemsWriter",
    addrint(lib.PyDictIterItem_Type): "PyDictIterItemWriter",
    addrint(lib.PyDictIterKey_Type): "PyDictIterKeyWriter",
    addrint(lib.PyDictIterValue_Type): "PyDictIterValueWriter",
    addrint(lib.PyDictKeys_Type): "PyDictKeysWriter",
    addrint(lib.PyDictProxy_Type): "PyDictProxyWriter",
    addrint(lib.PyDictValues_Type): "PyDictValuesWriter",
    addrint(lib.PyDict_Type): PyDictWriter,
    addrint(lib.PyEllipsis_Type): "PyEllipsisWriter",
    addrint(lib.PyEnum_Type): "PyEnumWriter",
    addrint(lib.PyFile_Type): "PyFileWriter",
    addrint(lib.PyFloat_Type): PyFloatWriter,
    # frozenset is the same as set, except for ob_type
    addrint(lib.PyFrozenSet_Type): PySetWriter,
    addrint(lib.PyFunction_Type): PyFunctionWriter,
    addrint(lib.PyGen_Type): "PyGenWriter",
    addrint(lib.PyGetSetDescr_Type): PyGetSetDescrWriter,
    addrint(lib.PyInstance_Type): PyInstanceWriter,
    addrint(lib.PyInt_Type): PyIntWriter,
    addrint(lib.PyList_Type): PyListWriter,
    addrint(lib.PyLong_Type): PyLongWriter,
    addrint(lib.PyMemberDescr_Type): PyMemberDescrWriter,
    addrint(lib.PyMemoryView_Type): "PyMemoryViewWriter",
    addrint(lib.PyMethod_Type): PyMethodWriter,
    addrint(lib.PyModule_Type): PyModuleWriter,
    # No need to special handling NullImporter. PyObjectWriter can handle it.
    # addrint(lib.PyNullImporter_Type): "PyNullImporterWriter",
    addrint(lib.PyProperty_Type): PyPropertyWriter,
    addrint(lib.PyRange_Type): "PyRangeWriter",
    addrint(lib.PyReversed_Type): "PyReversedWriter",
    addrint(lib.PySeqIter_Type): "PySeqIterWriter",
    addrint(lib.PySet_Type): PySetWriter,
    addrint(lib.PySlice_Type): "PySliceWriter",
    addrint(lib.PyStaticMethod_Type): generatewriter("staticmethod"),
    addrint(lib.PyString_Type): PyStringWriter,
    addrint(lib.PySuper_Type): "PySuperWriter",
    addrint(lib.PyTraceBack_Type): "PyTraceBackWriter",
    addrint(lib.PyTuple_Type): PyTupleWriter,
    addrint(lib.PyFrame_Type): PyFrameWriter,
    # Types that need serialization are mostly heap types.
    addrint(lib.PyType_Type): PyHeapTypeWriter,
    addrint(lib.PyUnicode_Type): PyUnicodeWriter,
    addrint(lib.PyWrapperDescr_Type): PyWrapperDescrWriter,
    # weakrefobject.h. The 3 types share a same instance struct.
    addrint(lib._PyWeakref_RefType): PyWeakReferenceWriter,
    addrint(lib._PyWeakref_ProxyType): PyWeakReferenceWriter,
    addrint(lib._PyWeakref_CallableProxyType): PyWeakReferenceWriter,
}

# Native non-heap types defined (usually outside libpython). Match by name for
# now.  (Ideally we should create dummy objects to match them exactly)
#
# Note: they are only needed if their instances need serialization. If a native
# extension only defines static native types, it can usually be handled just
# fine.
TYPENAME_WRITER_MAP = {
    # Objects/descrobject.c
    # PyMethodDescr_Type is not exposed in .h
    "classmethod_descriptor": PyMethodDescrWriter,
    "method_descriptor": PyMethodDescrWriter,
    # from extensions
    "itertools.count": generatewriter("countobject"),
    "_sre.SRE_Pattern": PatternObjectWriter,
    "operator.itemgetter": generatewriter("itemgetterobject"),
    "operator.attrgetter": generatewriter("attrgetterobject"),
    "operator.methodcaller": generatewriter("methodcallerobject"),
    "datetime.date": DatetimeDateWriter,
    "_random.Random": RandomObjectWriter,
    "thread.lock": ThreadLockWriter,
    "Struct": StructWriter,
    "unicodedata.UCD": UnicodeUCDWriter,
    "StgDict": CTypesStgDictWriter,
    "_ctypes.PyCSimpleType": PyHeapTypeWriter,
    "_ctypes.PyCPointerType": PyHeapTypeWriter,
    "cython_function_or_method": CythonFunctionWriter,
}


def PyObjectDetectTypeWriter(ptr, *args, **kwargs):
    """Detect the type of the Python object. Return a dedicated writer."""
    typtr = ptr.ob_type
    wtype = TYPEID_WRITE_MAP.get(ptrint(typtr), PyObjectWriter)
    if wtype is PyObjectWriter:
        # Try to find a better writer
        wtype2 = TYPENAME_WRITER_MAP.get(ffi.string(typtr.tp_name), wtype)
        if wtype2:
            wtype = wtype2
    if isinstance(wtype, str):
        raise NotImplementedError("%r %r %r" % (ptr, type(toobj(ptr)), wtype))
    return wtype(ptr, *args, **kwargs)


def cloneptr(dst, src, wtype=None, wargs=None, inline=False, realloc=False):
    """Serialize a typed object at src to DynamicBuffer.

    If dst is a DynamicBuffer, append the object to the buffer and return its
    offset (BufferPointer). Note: it will error out if the object is static
    in libraries (ex. True).

    If dst is a BufferPointer, append the object to the associated
    DynamicBuffer or skip writing the object if it's a library static object
    (ex. True). Write the pointer to the object at dst.

    wtype overrides the type of the Writer. Useful if type cannot be
    auto-detected (i.e. ptr is not a PyObject).

    wargs are additional keyword arguments passed to wtype.

    If inline is True, instead of writing the pointer to the object to dst,
    write the object content directly at dst.
    """
    # print("cloneptr %r %r %r %r %d %d" % (dst, src, wtype, wargs, inline, realloc))
    # Normalize src - if it's a Python object, convert to CFFI pointer
    if not isinstance(src, CFFI_TYPE):
        # TODO: When does this happen ??
        assert not isinstance(src, DynamicBuffer)
        src = cast("PyObject *", id(src))

    assert ptrint(src) == 0 or ptrint(src) > 100000, "Something is probably wrong"

    # Normalize dst
    if isinstance(dst, DynamicBuffer):
        dbuf = dst
    elif isinstance(dst, BufferPointer):
        dbuf = dst._dbuf
        # Short path: NULL or known pointer - no need to clone
        if src == ffi.NULL or dbuf.hasptr(src):
            if isobj(src) and inline:
                raise TypeError("known objects cannot be inlined")
            if not inline:
                dst.writeptr(src)
                return dst
            # Still possible to write duplicated data for non PyObject
            # content inline.
    else:
        raise TypeError("dst must be BufferPointer or DynamicBuffer")

    # Replace it on demand?
    src = dbuf.replaceptr(src)

    # Prepare writer
    if wtype is None:
        # Auto-detect writer type
        if getattr(src, "ob_type", None) is not None:
            wtype = PyObjectDetectTypeWriter
        elif typeof(src).cname == "char *":
            # Auto-detect C strings
            wtype = CArrayWriter
            assert not wargs
            wargs = {"count": len(ffi.string(src)) + 1, "itemtype": "char"}
        else:
            raise TypeError("cannot auto-detect writer type for %r" % src)
    writer = wtype(src, dbuf, **(wargs or {}))

    # Prepare reallocsize
    if realloc:
        reallocsize = writer.size()
    else:
        reallocsize = 0

    # Write it!
    if isinstance(dst, BufferPointer):
        dst = dst.cast(writer.typename)
        if inline:
            assert not realloc, "inline and realloc are exclusive"
            # print('inline src %x dst %x' % (ptrint(src), dst._offset))
            writer.writebodyat(dst)
        else:
            writer.writeptrat(dst, reallocsize=reallocsize)
        return dst
    else:
        assert not inline, "inline requires dst to be BufferPointer"
        assert not realloc, "realloc requires dst to be BufferPointer"
        return writer.write()


SET_DUMMY, DICT_DUMMY = _dummies()

pos = []


def dump(ptr, dbuf=None):
    """Serialize a typed object to dbuf. Return its pointer (BufferPointer).

    This is just a simple version of cloneptr for easier IPython debugging.
    """
    if dbuf is None:
        dbuf = db
    value = cloneptr(dbuf, ptr)
    pos.append(value._offset)
    return value


def load(offsets=pos, raw=False, dbuf=None):
    """De-serialize objects. This is to verify things work.
    A proper implementation would be in native code.

    If raw is True, return cffi pointers instead of actual
    Python objects. Useful for debugging.
    """
    if dbuf is None:
        dbuf = db
    assert isinstance(dbuf, DynamicBuffer)
    buf = dbuf._buf[:]
    bufptr = cast("PyByteArrayObject *", id(buf))

    # Leak "buf" - keep it alive.
    bufptr.ob_refcnt += 100

    # Reallocations
    bufstart = ptrint(bufptr.ob_bytes)
    print("bufstart %x len %d" % (bufstart, len(buf)))

    for offset, dlindex in dbuf._dloffsets:
        value = dbuf._readrawptr(offset)
        dlpath = dbuf._dlnames[dlindex]
        base = dlbase(dlpath)
        writerawptr(buf, offset, value + base)

    for offset in sorted(dbuf._bufoffsetset):
        value = dbuf._readrawptr(offset)
        writerawptr(buf, offset, value + bufstart)

    for offset in sorted(dbuf._symoffsetset):
        symid = dbuf._readrawptr(offset)
        obj = dbuf._evalvalues[symid]
        writerawptr(buf, offset, id(obj))

    for offset in dbuf._pylocks:
        value = ptrint(lib.PyThread_allocate_lock())
        writerawptr(buf, offset, value)

    for offset, size in dbuf._realloc:
        start = dbuf._readrawptr(offset)
        newptr = lib.PyMem_Malloc(size)
        ffi.memmove(newptr, ffi.cast("uint8_t *", bufstart + start), size)
        writerawptr(buf, offset, ptrint(newptr))

    # Experimental: Mark objects as tracked.
    # for gcoffset in dbuf._gcoffsets:
    #     print('Write GC offset %d' % gcoffset)
    #     objoffset = bufstart + gcoffset + sizeof('PyGC_Head')
    #     print(repr(toobj(objoffset)))
    #     gcheader = ffi.cast('PyGC_Head *', bufstart + gcoffset)
    #     lib.PyObject_GC_Track(cast('PyObject *', objoffset))

    # Skip handling _pytypeset: They are already ready.
    # (Because DynamicBuffer cannot be serialized so load() runs in a ready
    # environment)

    # Extract objects by just casting the addresses!
    result = []
    resultptr = cast("PyObject *", id(result))
    for offset in offsets:
        if isinstance(offset, BufferPointer):
            offset = offset._offset
        if raw:
            ptr = cast("PyObject *", offset + bufstart)
            typename = PyObjectDetectTypeWriter(ptr).TYPENAME
            ptr = cast(typename, ptr)
            result.append(ptr)
        else:
            lib.PyList_Append(resultptr, cast("PyObject *", offset + bufstart))

    for dlindex, dloffset, offset in dbuf._subclassfixups:
        addr = dlbase(dbuf._dlnames[dlindex]) + dloffset
        baseptr = cast("PyTypeObject *", addr)
        assert baseptr.ob_type == lib.PyType_Type
        # Add "offset" to that baseptr
        assert baseptr.tp_subclasses != ffi.NULL
        ptr = cast("PyObject *", offset + bufstart)
        ref = lib.PyWeakref_NewRef(ptr, ffi.NULL)
        if ref != ffi.NULL:
            lib.PyList_Append(baseptr.tp_subclasses, ref)

    return result


class RawCCode(str):
    pass


def ccode(obj):
    """Convert obj to C code"""
    if "nt" in sys.modules:
        # MSVC cannot support static str with > 65535 chars
        listtypes = (list, bytearray)
        strtypes = (str,)
    else:
        # Make bytearray readable
        listtypes = list
        strtypes = (str, bytearray)
    if isinstance(obj, RawCCode):
        return str(obj)
    elif isinstance(obj, tuple):
        return "{%s}" % (",".join(map(ccode, obj)))
    elif isinstance(obj, listtypes):
        result = "{"
        linesize = 2
        for i in obj:
            word = "%s," % ccode(i)
            linesize += len(word)
            if linesize > 500:
                result += "\n    "
                linesize = len(word)
            result += word
        return result.rstrip(",") + "}"
    elif isinstance(obj, strtypes):
        result = '"'
        linesize = 0
        for b in bytearray(obj):
            if b == 0:
                word = "\\0"
            elif b == 10:
                word = "\\n"
            elif b == 34 or b == 92:  # ", \\
                word = "\\%c" % b
            elif b == 63 and result.endswith("?"):  # ?
                # avoid writing ??x which might trigger -trigraphs warning
                word = '""?'
            elif b >= 32 and b < 127:
                if result.endswith("\\0"):
                    word = '""%c' % b
                else:
                    word = "%c" % b
                isescape = False
            else:
                word = "\\%03o" % b
                isescape = False
            linesize += len(word)
            if linesize > 500:
                result += '"\n    "'
                if word.startswith('""'):
                    word = word[2:]
                linesize = len(word)
            result += word
        result += '"'
        return result
    elif isinstance(obj, (int, long)):
        if obj >= 1000000:
            return "0x%x" % obj
        else:
            return str(obj)
    else:
        raise TypeError("Unable to convert %s to C code" % type(obj))


def _scantypes(dbuf):
    # XXX: This might be not enough. Need to check individual modules.

    # This list might be changed to opt-in, like only adding types for modules
    # not imported.
    # The list does not affect correctness. It's just noisy.
    BLACKLIST = set(
        """CArgObject _ctypes.CField _ctypes.CThunkObject _ctypes.DictRemover
        _hashlib.HASH _re2.RE2_Match _re2.RE2_Regexp _ssl._SSLSocket
        cStringIO.StringI cStringIO.StringO datetime.time datetime.timedelta
        datetime.tzinfo deque_iterator deque_reverse_iterator grp.struct_group
        hgext.extlib.pyrevisionstore.datastore itertools._grouper
        itertools.combinations itertools.combinations_with_replacement
        itertools.compress itertools.cycle itertools.dropwhile
        itertools.groupby itertools.izip_longest itertools.permutations
        itertools.product itertools.takewhile itertools.tee
        itertools.tee_dataobject osutil.stat parsers.index
        time.struct_time""".split()
    )
    added = []
    for typeobj in (
        object.__subclasses__() + list.__subclasses__() + dict.__subclasses__()
    ):
        if typeobj.__name__ in BLACKLIST:
            continue
        typeptr = toptr(typeobj)
        if dbuf.marktype(typeptr):
            added.append(typeobj)
    if added:
        sys.stderr.write("added PyType_Ready for %s\n" % added)


def codegen(dbufs, modname="preload"):
    code = """
#include "DynamicBuffer.cpp"

"""
    dbufgetters = []
    for dbuf in dbufs:
        name = dbuf.name
        funcname = "getdbuf%s" % name
        code += gendbuffunc(dbuf, name, funcname)
        dbufgetters.append(RawCCode("&" + funcname))

    code += """
static PyObject* mod;

typedef DynamicBuffer (*GetDynamicBufferFunc)();
static GetDynamicBufferFunc dbufgetters[] = %(dbufgetters)s;
static vector<DynamicBuffer> dbufs;

extern "C" {
PyMODINIT_FUNC init%(modname)s(void) {
  if (PyType_Ready(&PySerializedType)) return;
  mod = Py_InitModule3("%(modname)s", NULL, NULL);
  dbufs.reserve(len(dbufgetters));
  for (size_t i = 0; i < len(dbufgetters); ++i) {
    dbufs.push_back(dbufgetters[i]());
  }
  for (size_t i = 0; i < len(dbufgetters); ++i) {
    PySerializedObject *dbufobj;
    dbufobj = PyObject_New(PySerializedObject, &PySerializedType);
    if (!dbufobj) return;
    dbufobj->pdbuf = &dbufs[i];
    PyModule_AddObject(mod, dbufs[i].name.c_str(), (PyObject *)dbufobj);
  }
}
}
""" % {
        "modname": modname,
        "dbufgetters": ccode(dbufgetters),
    }

    with open("%s.cpp" % modname, "w") as f:
        f.write(code)


def gendbuffunc(dbuf, name, funcname):
    """Generate C++ code to construct a DynamicBuffer C++ object"""

    assert isinstance(dbuf, DynamicBuffer)
    if not dbuf.ptrmap:
        raise IndexError("nothing stored in %r" % dbuf)

    # Double check
    dbuf.ensureinitialized()

    # Final modifications
    _scantypes(dbuf)

    # Pick the first object
    objoffset = dbuf.firstobjoffset()

    # Append the end mark.
    buf = bytearray(dbuf._buf)

    # Special offsets should not overlap
    assert not (
        dbuf._bufoffsetset & dbuf._dloffsetset
    ), "Offset adjustments should not overlap"
    assert not (
        dbuf._bufoffsetset & dbuf._symoffsetset
    ), "Offset adjustments should not overlap"
    assert not (
        dbuf._dloffsetset & dbuf._symoffsetset
    ), "Offset adjustments should not overlap"

    # evalcode, in compiled form
    evals = []
    for i, code in enumerate(dbuf._evalcode):
        compiled = marshal.dumps(compile(code, "<evalcode[%d]>" % i, "eval"))
        count = dbuf._evalcounts[i]
        evals.append((code, list(bytearray(compiled)), count))

    dls = []
    for path in dbuf._dlnames:
        symbol = dlanysymbol(path)[0]
        dls.append((path, symbol))

    dlrelocs = []
    for bufoffset, dlindex in dbuf._dloffsets:
        dlrelocs.append((bufoffset, dlindex))

    pysubcls = []
    for dlindex, dloffset, bufoffset in dbuf._subclassfixups:
        pysubcls.append((dlindex, dloffset, bufoffset))

    pytypes = []
    for dlindex, dloffset in dbuf._pytypeset:
        pytypes.append((dlindex, dloffset))

    # sorted(set(path for _i, path in dbuf._dloffsets))
    return r"""
static DynamicBuffer %(funcname)s() {
  static uint8_t buf[] = %(buf)s;
  static BufOffset bufoffsets[] = %(bufoffsets)s;
  static BufOffset evaloffsets[] = %(evaloffsets)s;
  static ReallocReloc reallocrelocs[] = %(realloc)s;
  static DlReloc dlrelocs[] = %(dlreloc)s;
  static BufOffset pylocks[] = %(pylocks)s;
  static BufOffset pymods[] = %(pymods)s;
  static SubclassFixup pysubcls[] = %(pysubcls)s;
  static TypeReadyFixup pytypes[] = %(pytypes)s;
  static uint8_t importnative[] = %(compiledimportnative)s;

  DynamicBuffer dbuf;
  dbuf.buf = ToSizedArray(buf);
  dbuf.bufrelocates = ToSizedArray(bufoffsets);
  dbuf.evalrelocates = ToSizedArray(evaloffsets);
  dbuf.dlrelocates = ToSizedArray(dlrelocs);
  dbuf.reallocrelocates = ToSizedArray(reallocrelocs);
  dbuf.pylocks = ToSizedArray(pylocks);
  dbuf.pymods = ToSizedArray(pymods);
  dbuf.pysubcls = ToSizedArray(pysubcls);
  dbuf.pytypes = ToSizedArray(pytypes);
  dbuf.compiledimportnative = ToSizedArray(importnative);

  dbuf.name = %(name)s;
  dbuf.evals = %(evals)s;
  dbuf.dls = %(dls)s;
  dbuf.objoffset = %(objoffset)s;

  return dbuf;
}
""" % {
        "funcname": funcname,
        "name": ccode(name),
        "buf": ccode(buf),
        "bufoffsets": ccode(sorted(dbuf._bufoffsetset)),
        "evaloffsets": ccode(sorted(dbuf._symoffsetset)),
        "dlreloc": ccode(sorted(dbuf._dloffsets)),
        "realloc": ccode(sorted(dbuf._realloc)),
        "evals": ccode(evals),
        "dls": ccode(dls),
        "dlrelocates": ccode(sorted(dlrelocs)),
        "pylocks": ccode(sorted(dbuf._pylocks)),
        "pymods": ccode(sorted(dbuf._pymodset)),
        "pysubcls": ccode(sorted(pysubcls)),
        "pytypes": ccode(sorted(pytypes)),
        "compiledimportnative": ccode(list(bytearray(marshal.dumps(importnative.func_code)))),
        "objoffset": objoffset,
    }


# sys.stdin, out, err, modules
# posix.environ (for environment variables)

evalcode = [
    # This makes os.environ.data consistent with the new environment
    # "__import__('posix').environ",
    # native modules
    # "map(__import__, ['_ctypes', '_bsddb', 'sys', '_io', '_collections', '_socket'])",
    # "__import__('_ctypes').__dict__.values()",
    # stdin, stdout, stderr; file object cannot be serialized
    "imp.init_builtin('sys')",
    "[sys.stdin, sys.stdout, sys.stderr, sys.modules]",
    # "[v for k, v in __import__('sys').__dict__.items() if k in {'stdin', 'stdout', 'stderr', 'modules'}]",
    # see bsddb/db.py - it reexports bsddb: exec("from ._bsddb import __version__")
    # "__import__('_bsddb').__dict__.values()",
    # # io.py wants a lot from _io
    # "__import__('_io').__dict__.values()",
    # "__import__('_collections').__dict__.values()",
]

db = DynamicBuffer(
    name="main",
    evalcode=evalcode,
    replaces=[
        (ffi, None),
        (lib, None),
        (pos, None),
        (PtrWriter, None),
        (dump, None),
        (load, None),
        (codegen, None),
    ],
)
