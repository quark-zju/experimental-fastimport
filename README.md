Experimental fast Python object serializating.

## The idea

The idea is to serialize Python objects recursively as their raw memory representations (think about `memcpy` a `PyObject` and its dependencies), then object loading can be just a mmap, followed by:
- Adjust pointers. Libraries might be loaded at different places due to ASLR. So related pointers (ex. types, subclasses, reference to other objects) need to be adjusted.
- Side effects. For example, the side effects of creating mutexes needs to be re-done. Native module initialization might need to be re-done (and can be tricky).  

The ideal end result is that `sys.modules` can be serialized and loaded this way to achieve fast module import, followed by adjusting some states like `os.environ`.

## Implementation

I used `cffi` to read Python source code and figure out different types of Python object's underlying structures. Then implement serialization for each type involved. Serailization produces metadata about how to do pointer adjustments so deserialization does not need to be implemented per each type.

## Outcome

The experiment was for modules used by `hg`, and was able to get 80% hg's integration tests passing on Linux. I didn't continue fixing the remaining issues. Windows support is missing.

## Learnings

- Performnace:
  - Pointer adjustment takes a long time. Loading all `hg` modules takes about 50ms.
  - ASLR is annoying for performance.
  - Mmapping the serialized buffer at a fixed offset can avoid the "relative object" pointer adjustments, but is not noticably faster. Lots of pointers still need to be changed for basic types like `PyBytes_Type`. I haven't done experiments when libpython is not ASLR-ed but I guess that might help performance.
- Correctness:
  - `Dict[object, ...]` is a source of test failures, since `id(obj)` can change. It wasn't fixed. Ideally the usage is low and we point it out during serialization.
  - `ctypes` is a pain to handle. In this implementation, pointers to libraries like `libfoo.so` are tracked as `libfoo.so+offset` and adjusted with the new `libfoo.so` location. This is general purposed for all native libraries. It worked relatively well.
