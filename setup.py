from distutils.core import setup
from Cython.Build import cythonize
from distutils.core import Extension

import os

nt = os.name == "nt"

mods = []

for name in ["preload", "foo"]:
    filename = name + ".cpp"
    if not os.path.exists(filename):
        continue
    if nt:
        mods.append(Extension(name, sources=[filename]))
    else:
        mods.append(
            Extension(
                name,
                sources=[filename],
                extra_compile_args=["-g", "-std=c++11", "-O3", "-fopenmp"],
                extra_link_args=["-lgomp"],
            )
        )

setup(ext_modules=mods)
