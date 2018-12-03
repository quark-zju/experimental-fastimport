from distutils.core import setup
from Cython.Build import cythonize
from distutils.core import Extension

import os

nt = os.name == "nt"

if nt:
    mods = [
        Extension("foo", sources=["foo.cpp"], extra_compile_args=[], extra_link_args=[])
    ]
else:
    mods = [
        Extension(
            "foo",
            sources=["foo.cpp"],
            extra_compile_args=["-g", "-std=c++14", "-O3", "-fopenmp"],
            extra_link_args=["-lgomp"],
        )
    ]

setup(ext_modules=mods)
