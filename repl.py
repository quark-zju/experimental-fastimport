import gc
gc.disable()

import os, sys, preload

# preload.setdebug(True)
# preload.setmmap(False)
for k, v in preload.modules().items():
    if k == 'code': #or k == 'functools':
        continue
    if k not in sys.modules:
        sys.modules[k] = v
    else:
        # print('already loaded: %s' % k)
        sys.modules[k] = v

# print(id(sys.modules['codecs']))
# print(id(sys.modules['encodings.utf_8'].codecs))
# print(id(codecs))
# print(id(sys.modules['encodings.utf_8'].decode.func_globals['codecs']))

# print(codecs.utf_8_decode)
# print(preload.contains(codecs))
# print(preload.contains(_codecs))
# import code
# print(preload.contains(code)) # True ?

import threading
threading._shutdown = threading._MainThread()._exitfunc

# import code
# code.interact()

import IPython
IPython.embed()
