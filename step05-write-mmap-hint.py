#!/bin/env python2

import resource
import sys

from c import writerawptr, readrawptr

FILENAME = "preload.so"
MARKER = b"\0BUFENDSHERE\090a189a6ca3c"


if __name__ == "__main__":
    content = bytearray(open(FILENAME, "rb").read())

    def locate(needle, after=False):
        offset = content.find(needle)
        if offset == -1:
            raise RuntimeError("cannot find %s" % needle)
        elif content.find(needle, offset + 1) != -1:
            raise RuntimeError("multiple %s found" % needle)
        if after:
            offset += len(needle)
        return offset

    patchedoffset = locate("__PATCH_IS_PATCHED__\0", after=True)
    if readrawptr(content, patchedoffset):
        print("%s is already patched" % FILENAME)
        sys.exit(0)

    movedoffset = locate("__PATCH_MOVED_OFFSET__\0", after=True)
    infileoffset = locate("__PATCH_OFFSET_IN_FILE__\0", after=True)

    assert readrawptr(content, movedoffset) == 0
    assert readrawptr(content, infileoffset) == 0

    bufstart = locate("__DBUF_START_MARK__")
    bufend = locate("__DBUF_END_MARK__")
    pagesize = resource.getpagesize()

    if bufstart % pagesize != 0:
        # shift bufstart:bufend right
        newbufstart = (bufstart // pagesize + 1) * pagesize
        newbufend = newbufstart + bufend - bufstart
        print(
            "moving %d:%d -> %d:%d to align to page size"
            % (bufstart, bufend, newbufstart, newbufend)
        )
        content[newbufstart:newbufend] = content[bufstart:bufend]
        print("zeroing out %d:%d" % (bufstart, newbufstart))
        content[bufstart:newbufstart] = b"\0" * (newbufstart - bufstart)
        writerawptr(content, movedoffset, newbufstart - bufstart)
    else:
        newbufstart = bufstart
    writerawptr(content, infileoffset, newbufstart)
    writerawptr(content, patchedoffset, 1)
    with open(FILENAME, "wb") as f:
        f.write(content)
    print("%s patched" % FILENAME)
