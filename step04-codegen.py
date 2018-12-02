#!/bin/env python2

from c import dump, load, codegen, PtrWriter, db, pos
import c
import sys

# Patch uuid so it does not contain a reference to an opened library (which
# has dependencies on ctypes internals. Serialization of instances of ctypes
# types are not implemented).


modnames = [
    # # hg modules
    "hgdemandimport",
    "hgdemandimport.demandimportpy2",
    "mercurial",
    "mercurial.extensions",
    "mercurial.ancestor",
    "mercurial.archival",
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
    "hgext",
    "hgext.absorb",
    "hgext.amend",
    "hgext.arcdiff",
    "hgext.automv",
    "hgext.blackbox",
    "hgext.checkmessagehook",
    "hgext.chistedit",
    "hgext.clienttelemetry",
    "hgext.clindex",
    "hgext.commitcloud",
    "hgext.configwarn",
    "hgext.conflictinfo",
    "hgext.convert",
    "hgext.copytrace",
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
    "hgext.fastmanifest",
    "hgext.fbconduit",
    "hgext.fbhistedit",
    "hgext.fixcorrupt",
    "hgext.fsmonitor",
    "hgext.githelp",
    "hgext.gitlookup",
    "hgext.grpcheck",
    "hgext.hgevents",
    "hgext.hgsubversion",
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
    "hgext.myparent",
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
    "mercurial.statprof",
    "hgext.infinitepushbackup",
    "ConfigParser",
    "hgext.fastannotate.support",
    "encodings.ascii",
    "encodings.utf_8",
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

print("serializing")

import ctypes, ctypes._endian, os, sys, uuid
import atexit, threading

# import uuid
uuid._UuidCreate = None
uuid._uuid_generate_time = None
uuid._uuid_generate_random = None
uuid.lib = None


db = c.DynamicBuffer(
    evalcode=[
        # Those are printed by "python -Sc 'import sys; print(sys.modules.keys())'". encodings.utf_8 ?
        "[sys.modules[k] for k in ['zipimport', 'encodings.__builtin__', '_codecs', 'signal', 'encodings', 'encodings.codecs', '__builtin__', 'sys', 'encodings.aliases', 'exceptions', 'encodings.encodings', '_warnings', 'codecs']]",
        "[sys, sys.stdin, sys.stdout, sys.stderr, sys.modules, sys.argv, os, os.environ]",
        # native modules
        "__import__('_ctypes').__dict__.values()",
        "__import__('_collections').__dict__.values()",
    ],
    replaces=[
        (ctypes.memmove, None),
        (ctypes.memset, None),
        (ctypes._cast, None),
        (ctypes._string_at, None),
        (ctypes._wstring_at, None),
        (ctypes.pythonapi, None),
        (ctypes._endian.BigEndianStructure, None),
        (ctypes._endian.LittleEndianStructure, None),
        (ctypes._c_functype_cache, {}),
        (atexit._exithandlers, []),
        (threading._active, {}),
    ],
)

# Whitelist bser.so
c.PyModuleWriter.WHITELIST.add("bser.so")

dump(d, dbuf=db)

print("generating code")
codegen(dbuf=db)

if "d" in sys.argv:
    print("dump ptrmap")
    with open("ptrmap", "w") as f:
        for k, v in sorted(db.ptrmap.iteritems()):
            f.write("%d %d\n" % (k, v))

if "v" in sys.argv:
    v = load(pos, dbuf=db)

print("done")

if "i" in sys.argv:
    __import__("IPython").embed()
