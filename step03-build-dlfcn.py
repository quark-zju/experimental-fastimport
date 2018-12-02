#!/usr/bin/env python

from cffi import FFI

import sys

builder = FFI()

if "nt" in sys.modules:
    # From dladdr manpage
    builder.cdef(
        """
    typedef struct {
        const char *dli_fname;
        void       *dli_fbase;
        const char *dli_sname;
        void       *dli_saddr;
    } Dl_info;
    
    int dladdr(void *addr, Dl_info *info);
    void *dlopen(const char *filename, int flags);
    void *dlsym(void *handle, const char *symbol);
    void dlrefresh(void);
    
    #define RTLD_LAZY ...
    #define RTLD_NOW ...
            """
    )

    builder.set_source(
        "dlfcn",
        """
    #include "windl.h"
    """,
        source_extension=".cpp",
    )
else:
    # From dladdr manpage
    builder.cdef(
        """
    typedef struct {
        const char *dli_fname;
        void       *dli_fbase;
        const char *dli_sname;
        void       *dli_saddr;
    } Dl_info;

    int dladdr(void *addr, Dl_info *info);
    int dladdr1(void *addr, Dl_info *info, void **extra_info, int flags);
    void *dlopen(const char *filename, int flags);
    int dlclose(void *handle);
    void *dlsym(void *handle, const char *symbol);
    void *dlvsym(void *handle, char *symbol, char *version);
    char *dlerror(void);

    #define LM_ID_BASE ...
    #define LM_ID_NEWLM ...
    #define RTLD_DEEPBIND ...
    #define RTLD_DL_LINKMAP ...
    #define RTLD_DL_SYMENT ...
    #define RTLD_GLOBAL ...
    #define RTLD_LAZY ...
    #define RTLD_LOCAL ...
    #define RTLD_NODELETE ...
    #define RTLD_NOLOAD ...
    #define RTLD_NOW ...

    void dlrefresh(void);
            """
    )

    builder.set_source(
        "dlfcn",
        """
    #ifndef _GNU_SOURCE
    # define _GNU_SOURCE
    #endif
    #include <dlfcn.h>

    void dlrefresh() {}
    """,
        libraries=["dl"],
    )

if __name__ == "__main__":
    builder.compile(verbose=True)
