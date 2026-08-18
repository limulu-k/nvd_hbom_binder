#!/usr/bin/env python3
"""Read git blobs without a working tree, so Clovery can run on a lean clone.

``apply_compat_patch.py`` installs a copy of this module next to Clovery's own
scripts and rewrites their working-tree reads to call it.  Clovery runs each
step as ``python3 <n>_*.py`` from its own directory, so that directory is
``sys.path[0]`` and a plain ``from clovery_lean import ...`` resolves.

The paper (Sect. 4) needs exactly two git reads per target function::

    git log --follow --diff-filter=AMD --name-status --pretty=format:"%H %ci" -- <file>
    git log -1 <commit id> -L:<function name>:<path>

The implementation goes much further: ``getFuncCode`` runs ``git checkout -f``
for every commit in the function history, and ``tagDetection`` runs one for
*every tag* before reading the file off the working tree - 512 full-tree
checkouts on rsyslog, for a repository from which exactly one file is ever
read.  Every one of those reads is served by ``git show <rev>:<path>`` here
instead, which is what lets the clone be ``--filter=blob:none --no-checkout``.

All git commands run against the process's current directory, which is the
clone Clovery is working on - the same assumption the code being patched makes.
"""

from __future__ import annotations

import os
import subprocess


DEFAULT_SCRATCH_DIR = os.path.join("Evalu", "garbage")

# Overwritten by ``set_scratch_dir`` at import time of the patched script; the
# env var and the default only matter when this module is used on its own.
_scratch_dir = os.environ.get("CLOVERY_SCRATCH_DIR") or DEFAULT_SCRATCH_DIR
_blob_seq = [0]


def set_scratch_dir(path):
    """Point blob materialization at Clovery's ``Garbage`` directory.

    The patched script calls this at module level, so a fork-started pool
    worker inherits the value and a spawn-started one re-runs the call.
    """

    global _scratch_dir
    _scratch_dir = str(path)


def blob_dir():
    path = os.path.join(_scratch_dir, "blobs")
    os.makedirs(path, exist_ok=True)
    return path


def materialize_blob(rev, path):
    """Write ``<rev>:<path>`` to a temp file; no working tree, no checkout.

    Returns the temp path, or None when the blob does not exist at that rev -
    which is the normal answer for a tag predating the file, and the caller
    treats it as "file absent here" rather than as an error.

    Names are pid+counter unique because Clovery fans these calls out across a
    24-worker process pool over one shared scratch directory.
    """

    try:
        data = subprocess.check_output(
            ["git", "show", "%s:%s" % (rev, path)], stderr=subprocess.DEVNULL
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    _blob_seq[0] += 1
    ext = path.rsplit(".", 1)[-1] if "." in os.path.basename(path) else "c"
    out = os.path.join(
        blob_dir(), "b%d_%d.%s" % (os.getpid(), _blob_seq[0], ext)
    )
    with open(out, "wb") as handle:
        handle.write(data)
    return out


def prefetch_blobs(revs, paths):
    """Resolve every ``<rev>:<path>`` in one promisor round trip.

    In a blobless clone each individual read costs its own fetch; the tag scan
    reads the same file at every tag, so that is one network round trip per
    tag.  ``git cat-file --batch-check`` resolves the whole list in a single
    pass, and git requests all the still-missing objects together.

    Best effort by design: this is a warm-up, and every read it covers is
    repeated by ``materialize_blob``, which fetches on demand anyway.
    """

    if not revs or not paths:
        return
    spec = "".join("%s:%s\n" % (rev, path) for rev in revs for path in paths)
    try:
        subprocess.run(
            ["git", "cat-file", "--batch-check"],
            input=spec.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass
