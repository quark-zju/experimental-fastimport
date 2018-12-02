from distutils.core import setup
from Cython.Build import cythonize
from distutils.core import Extension

setup(
    ext_modules=[
        Extension(
            "preload",
            sources=["preload.c"],
            extra_compile_args=["-g", "-march=native", "-std=c99"],
            extra_link_args=[],
        ),
    ]
)
