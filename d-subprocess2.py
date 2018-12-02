#!/bin/env python2

import os, sys, time
import foo
v = foo.load()

assert v.Popen in object.__subclasses__()

print(os.getpid())
while not os.path.exists('/tmp/cont'):
    time.sleep(1)

proc = v.Popen(['cat'], stdin=v.PIPE, stdout=v.PIPE)
print(proc.communicate('foo'))

