import os, sys, preloadhg

# sys.modules.update(preloadhg.modules())

import gc
gc.disable()

import threading
# threading._shutdown = threading._MainThread()._exitfunc

# import code
# code.interact()

import IPython
IPython.embed()
