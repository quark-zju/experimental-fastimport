#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import c
import sys

# Patch uuid so it does not contain a reference to an opened library (which
# has dependencies on ctypes internals. Serialization of instances of ctypes
# types are not implemented).


modnames = [
    # "ConfigParser",
    # "Queue",
    # "UserDict",
    # "encodings",
    # "_lsprof",
    # "abc",
    # 'anydbm',
    # "array",
    # "base64",
    # "binascii",
    # "bz2",
    # "calendar",
    # "code",
    # "codecs",
    # "collections",
    # "contextlib",
    # "copy",
    # 'ctypes', # native _ctypes private types ...
    # "datetime",
    # "difflib",
    # "email",
    # "email.charset",
    # "email.header",
    # "email.message",
    # "errno",
    # "fcntl",
    # "filecmp",
    # "ftplib",
    # "functools",
    # "gc",
    # "getopt",
    # "getpass",
    # "gettext",
    # "glob",
    # "grp",
    # 'gzip', # iobase_iter not in libpython - solved
    # "hashlib",
    # "heapq",
    # # 'hgdemandimport',
    # "imp",
    # "inspect",  # uninitialized bytes
    # 'io', # not in libpython
    # "itertools",
    # "json",
    # "locale",
    # 'logging',
    # 'lz4', # native
    # "mercurial",
    # "mimetypes",
    # "mmap",
    # "operator",
    # "os",
    # "pdb",
    # "pkgutil",
    # "platform",
    # "posixpath",
    # "pwd",
    # 'random',
    # "re",
    # "resource",
    # "select",
    # "shlex",
    # "shutil",
    # "signal",
    # 'smtplib',
    # "socket",
    # "ssl",
    # "stat",
    # "string",
    # "struct",
    # "subprocess",
    # "sys",
    # "tarfile",
    # 'tempfile', # thread.lock incomplete write
    # "termios",  # native
    # "textwrap",  # segfault :/
    # 'threading', # thread.lock
    # "time",
    # "traceback",
    # "tty",
    # "types",
    # "unicodedata",
    # 'uuid', # ctypes types are private ...
    # "warnings",
    # "weakref",
    # "xml.dom.minidom",
    # "zipfile", # iobase_iter
    # "zlib",
    # # hg modules
    "mercurial.extensions",
    "mercurial.ancestor",
    "mercurial.archival", # gzip.GzipFile
    "mercurial.bookmarks",
    "mercurial.branchmap",
    "mercurial.bundle2",
    "mercurial.bundlerepo",
    "mercurial.byterange",
    "mercurial.changegroup",
    "mercurial.changelog",
    "mercurial.color",
    "mercurial.config",
    "mercurial.configitems",
    "mercurial.connectionpool",
    "mercurial.context",
    "mercurial.copies",
    "mercurial.crecord",
    "mercurial.dagop",
    "mercurial.dagparser",
    "mercurial.dagutil",
    "mercurial.debugcommands",
    "mercurial.destutil",
    "mercurial.dirstate",
    "mercurial.dirstateguard",
    "mercurial.discovery",
    "mercurial.exchange",
    "mercurial.filelog",
    "mercurial.filemerge",
    "mercurial.fileset",
    "mercurial.formatter",
    "mercurial.graphmod",
    "mercurial.hbisect",
    "mercurial.httpclient",
    "mercurial.httpconnection",
    "mercurial.httppeer",
    "mercurial.localrepo",
    "mercurial.lock",
    "mercurial.logexchange",
    "mercurial.mail",
    "mercurial.manifest",
    "mercurial.match",
    "mercurial.mdiff",
    "mercurial.merge",
    "mercurial.mergeutil",
    "mercurial.minirst",
    "mercurial.namespaces",
    "mercurial.node",
    "mercurial.obsolete",
    "mercurial.obsutil",
    "mercurial.parser",
    "mercurial.patch",
    "mercurial.pathutil",
    "mercurial.peer",
    "mercurial.phases",
    "mercurial.policy",
    "mercurial.progress",
    "mercurial.pushkey",
    "mercurial.rcutil",
    "mercurial.repository",
    "mercurial.repoview",
    "mercurial.revlog",
    "mercurial.revset",
    "mercurial.revsetlang",
    "mercurial.rewriteutil",
    "mercurial.rust",
    "mercurial.scmposix",
    "mercurial.scmutil",
    "mercurial.server",
    "mercurial.setdiscovery",
    "mercurial.similar",
    "mercurial.simplemerge",
    "mercurial.smartset",
    "mercurial.sshpeer",
    "mercurial.sshserver",
    "mercurial.sslutil",
    "mercurial.store",
    "mercurial.streamclone",
    "mercurial.subrepo",
    "mercurial.tags",
    "mercurial.templatefilters",
    "mercurial.templatekw",
    "mercurial.templater",
    "mercurial.transaction",
    "mercurial.treediscovery",
    "mercurial.txnutil",
    "mercurial.url",
    "mercurial.urllibcompat",
    "mercurial.vfs",
    "mercurial.wireproto",
    "mercurial.worker",
    "mercurial.__version__",
    "hgext.absorb",
    "hgext.amend",
    "hgext.arcdiff", # datetime issues
    "hgext.automv",
    "hgext.blackbox",
    "hgext.checkmessagehook",
    "hgext.chistedit",
    "hgext.clienttelemetry",
    "hgext.clindex",
    "hgext.configwarn",
    "hgext.conflictinfo",
    "hgext.convert",
    "hgext.copytrace",
    "hgext.commitcloud",
    "hgext.crdump",
    "hgext.debugcommitmessage",
    "hgext.debugshell",
    "hgext.dialect",
    "hgext.directaccess",
    "hgext.dirsync",
    "hgext.extlib",
    "hgext.extorder",
    "hgext.extutil",
    "hgext.fastannotate",
    "hgext.fastlog",
    "hgext.fbconduit",
    "hgext.fbhistedit",
    "hgext.fixcorrupt",
    "hgext.fsmonitor",
    "hgext.githelp",
    "hgext.gitlookup",
    "hgext.grpcheck",
    "hgext.hgevents",
    # "hgext.hgsubversion",
    "hgext.hiddenerror",
    "hgext.histedit",
    "hgext.infinitepush",
    "hgext.journal",
    "hgext.lfs",
    "hgext.logginghelper",
    "hgext.lz4revlog",
    "hgext.mergedriver",
    "hgext.morecolors",
    "hgext.morestatus",
    "hgext.patchbomb",
    "hgext.patchrmdir",
    "hgext.phabdiff",
    "hgext.phabstatus",
    "hgext.phrevset",
    "hgext.progressfile",
    "hgext.pullcreatemarkers",
    "hgext.purge",
    "hgext.pushrebase",
    "hgext.rage",
    "hgext.rebase",
    "hgext.remotefilelog",
    "hgext.remotenames",
    "hgext.reset",
    "hgext.sampling",
    "hgext.schemes",
    "hgext.share",
    "hgext.shelve",
    "hgext.sigtrace",
    "hgext.simplecache",
    "hgext.smartlog",
    "hgext.sparse",
    "hgext.sshaskpass",
    "hgext.stat",
    "hgext.strip",
    "hgext.traceprof",
    "hgext.treemanifest",
    "hgext.tweakdefaults",
    "hgext.undo",
]

def _resolvenestedmodules(mod, name):
    """resolve nested modules

    __import__('x.y.z') returns module x when no fromlist is specified.
    This function resolves it and return the module "z".
    """
    components = name.split(".")
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod

d = {}
for name in modnames:
    d[name] = _resolvenestedmodules(__import__(name), name)

print('serializing')



# Patching

import ctypes, ctypes._endian
del ctypes.memmove
del ctypes.memset
del ctypes._cast
del ctypes._string_at
del ctypes._wstring_at
del ctypes.pythonapi
ctypes._c_functype_cache.clear()
del ctypes._endian.memmove
del ctypes._endian.memset
del ctypes._endian.pythonapi
del ctypes._endian.BigEndianStructure
del ctypes._endian.LittleEndianStructure
del ctypes._endian.Structure
del ctypes.BigEndianStructure
del ctypes.LittleEndianStructure
# import uuid - uuid is no longer used
# uuid._UuidCreate = None
# uuid._uuid_generate_time = None
# uuid.lib = None

# Whitelist bser.so
c.PyModuleWriter.WHITELIST.add("bser.so")


#import ipdb
# ipdb has side effect on __builtins__
# with ipdb.launch_ipdb_on_exception():
dump(d)


print('generating code')
codegen()

v = load(pos)

__import__('IPython').embed()
