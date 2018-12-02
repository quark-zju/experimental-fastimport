from distutils.core import setup
from Cython.Build import cythonize
from distutils.core import Extension

setup(
    ext_modules=[
        # Extension(
        #     "preloados",
        #     sources=["preloados.c"],
        #     extra_compile_args=["-g", "-std=c99", "-O3", "-fopenmp", "-march=native"],
        #     extra_link_args=["-lgomp"],
        # ),
        # Extension(
        #     "preloadhg",
        #     sources=["preloadhg.c"],
        #     extra_compile_args=["-g", "-std=c99", "-O3", "-fopenmp", "-march=native"],
        #     extra_link_args=["-lgomp"],
        # ),
        Extension(
            "foo",
            sources=["foo.cpp"],
            extra_compile_args=["-g", "-std=c++14", "-O3", "-fopenmp"],
            extra_link_args=["-lgomp"],
        ),
    ]
)
