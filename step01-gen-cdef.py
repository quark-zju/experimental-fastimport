#!/usr/bin/env python

import ctypes
import glob
import os
import pycparser
import re
import subprocess
import sys
import tempfile

PYTHON_SOURCE = os.environ.get("PYTHON_SOURCE", os.path.expanduser("~/cpython-hg"))

if not os.path.exists("%s/Include/Python.h" % PYTHON_SOURCE):
    raise RuntimeError("Please define PYTHON_SOURCE to path of the Python 2.7 source")

WANTED_STRUCTS = [
    # _struct
    "PyStructObject",
    "formatcode",
    "formatdef",
    # threadmodule
    "lockobject",
    # _randommodule
    "RandomObject",
    # _collectionsmodule
    "defdictobject",
    # datetime
    "PyDateTime_Date",
    # Capsule
    "PyCapsule",
    # sre
    "PatternObject",
    "MatchObject",
    # unicodedata.c
    "PreviousDBVersion",
    "change_record",
    # _ctypes.h
    "StgDictObject",
    # ffi.h
    "ffi_type",
]


def cpp(path=None, code=None):
    args = ["cpp"]
    if code:
        p = subprocess.Popen(
            args + ["-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        return p.communicate(code)[0]
    elif path:
        return subprocess.check_output(args + [path])
    else:
        raise TypeError("either path or code needs exist")


def extractstructs(paths):
    """Find PyObject structs in given defined in public .h. Return C code
    containing them.
    """
    # poor-man's "struct" extractor
    structre = re.compile(
        "\n(?:typedef )?struct [^#{]*{\n.*?\n}[^\n;]*;", flags=re.M | re.S
    )
    result = ""
    for path in paths:
        print(path)
        content = open(path).read()
        header = "\n/* from %s */\n" % os.path.relpath(path, PYTHON_SOURCE)
        for struct in structre.findall(content):
            shouldinclude = False
            for wanted in WANTED_STRUCTS:
                if struct.endswith("} %s;" % wanted) or struct.startswith(
                    "\nstruct %s" % wanted
                ):
                    shouldinclude = True
                    break
            if not shouldinclude:
                shouldinclude = " PyObject_" in struct and seemssupported(struct)
            # Make sure it does not contain unknown fields
            if shouldinclude:
                # Special cases
                if struct.endswith(" RandomObject;"):
                    # "#define N 624"
                    struct = struct.replace("[N]", "[624 /* N in _randommodule.c */]")
                elif struct.endswith(" PatternObject;"):
                    struct = (
                        """
#ifdef Py_USING_UNICODE
# define SRE_CODE Py_UCS4
#else
# define SRE_CODE unsigned int
#endif
%s
"""
                        % struct
                    )
                elif struct.endswith(" StgDictObject;"):
                    # Minimal dependencies for StgDictObject
                    struct = (
                        """
// libffi - there are different flavors - libffi, libffi_osx, libffi_msvc,
// libffi_arm_wince. But ffi_type is the same in all of them (as of Python
// 2.7.13). This struct is used by ctypes.
typedef struct _ffi_type
{
  size_t size;
  unsigned short alignment;
  unsigned short type;
  struct _ffi_type **elements;
} ffi_type;

// They are function pointers. But we don't care about the details.
#define GETFUNC void *
#define SETFUNC void *
#define PARAMFUNC void *

%s
"""
                        % struct
                    )
                result += "\n%s%s\n" % (header, struct)
                header = ""
    return result


def seemssupported(structcode):
    """Test if a struct contains only known typed fields"""
    # LINKCELLS is defined in itertoolsmodule.c
    if "[LINKCELLS]" in structcode or "[N]" in structcode:
        return False
    elif "struct kevent" in structcode:
        return False

    code = ""
    for name in [
        "PyObject",
        "Py_ssize_t",
        "uint32_t",
        "PyByteArrayObject",
        "PyTupleObject",
        "PyListObject",
        "PyTypeObject",
        "PyWrapperDescrObject",
        "PyDictObject",
    ]:
        # Just define them
        code += "typedef int %s;\n" % name
    code += cpp(code=structcode.replace("PyObject_HEAD", ""))
    parser = pycparser.CParser()
    try:
        # The parser complains about unknown types.
        parser.parse(code)
        return True
    except Exception as ex:
        return False


def extractpythondefs(code):
    """Look through cpp-expanded code. Filter them so only Python definitions
    are left. Return filtered C code.
    """
    # Scan through the content and extract useful stuff
    currentfile = "/"
    needuncomment = False
    newcontent = ""
    lib = ctypes.CDLL("libpython2.7.so")
    funcre = re.compile(
        "^\s*(?:int|void|Py[A-Za-z_]*|char|size_t|ssize_t)[ \*]+([A-Za-z0-9_]+)\("
    )
    for line in code.splitlines(True):
        # cpp writes file name as "#" comments. For example:
        # # 106 "object.h"
        if line.startswith("#"):
            currentfile = line.split()[2][1:-1]
        # Only include definitions in python
        if "python" in currentfile:
            # Remove parts incompatible with cffi:
            # __attribute__, va_list
            if "__attribute__" in line:
                # Good enough for Python.h
                line = line.replace("__attribute__", "/* __attribute__").replace(
                    "));", ")) */;"
                )
            if "va_list" in line or "PyArg_VaParse" in line:
                # Not perfect. But good enough for Python.h.
                line = "// %s" % line
            funcmatch = funcre.match(line)
            if funcmatch:
                # Verify if the function actually exists
                funcname = funcmatch.group(1)
                if getattr(lib, funcname, None) is None:
                    sys.stderr.write("warning: %s does not exist\n" % funcname)
                    # Not perfect. But good enough for Python.h.
                    assert not needuncomment
                    line = "/* %s" % line
                    needuncomment = True
            if needuncomment and ");" in line:
                line = line.replace(");", "); */")
                needuncomment = False
            if "sizeof" in line:
                # Hacky. But seems enough for Python.h on x64.
                line = line.replace("sizeof(union _gc_head_old)", "32")
            newcontent += line

    return newcontent


def main():
    paths = []
    for pattern in [
        "Objects/*.c",
        "Modules/*.c",
        "Modules/sre.h",
        "Modules/_ctypes/ctypes.h",
    ]:
        paths += list(glob.glob("%s/%s" % (PYTHON_SOURCE, pattern)))

    structs = extractstructs(paths)
    with open("python-structs.h", "w") as f:
        f.write(
            "// This file is @generated by gen_cdef.py\n"
            "// It contains more definitions of C structs\n\n"
        )
        f.write(structs)

    expanded = extractpythondefs(cpp("python-defs.h"))
    with open("cpyffi-cdef.h", "w") as f:
        f.write(
            "// This file is @generated by gen_cdef.py\n"
            "// It is to be feed into cffi.FFI().cdef\n\n"
        )
        f.write(expanded)


if __name__ == "__main__":
    main()