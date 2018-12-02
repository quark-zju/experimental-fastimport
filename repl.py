import sys, preloados
sys.modules.update(preloados.modules())

import os, sys, preloadhg

# preloadhg.setdebug(1)
sys.modules.update(preloadhg.modules())
print('pid %s' % os.getpid())

import gc
gc.disable()

# import threading
# threading._shutdown = threading._MainThread()._exitfunc

# import code
# code.interact()

import IPython
IPython.embed()
