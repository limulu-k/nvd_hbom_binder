#!/usr/bin/env python3
"""Make an upstream Clovery checkout runnable on a current toolchain.

Upstream (https://github.com/kimdu0/clovery) ships CRLF files and assumes an
older Joern, so a ``.patch`` is fragile.  This applies the same edits by exact
string replacement, preserving each file's original line endings, and is
idempotent - running it twice is a no-op.

    python scripts/clovery/apply_compat_patch.py --clovery clovery

An edit whose anchor is missing is a **failure**, not a warning: the checkout
would run with some fixes silently absent, and each of these fixes stands
between the pipeline and a crash or a wrong result.  The exit code is non-zero
whenever any edit could not be applied.

Lean-mode logic lives in ``clovery_lean.py`` and is installed into the checkout
as a real module, not injected as source text, so it stays lintable and
testable.  The patch only inserts the import.

Fixes, in order:

1-3. ``ctagsPath`` is hard-coded to a path that does not exist.  In
     3_clovery_cpg.py this silently breaks step 5 (``II_getHistory``): the
     ctags call fails inside a bare ``except``, leaving ``old_astString``
     unbound, so every CVE errors out.
  4. 1_cve_collector.py hard-codes six test CVEs (the README says to delete
     them).  Replaced with an optional ``CLOVERY_CVE_FILTER`` env var.
  5. ``all_errors.extend(error_log)`` crashes because the mapped function
     returns None.
  6. Current Joern no longer renders ``id = <n>L`` inside ``Call(...)``, so
     step 4 dies with IndexError.  The query now asks for "<id>,<line>" pairs
     and the parser reads that instead.
  7. Two NameErrors at the tail of steps 6 and 7 (``repo``, ``safeTagCombiPath``).
8-9. Two defects that turn a failed analysis into a clean "not vulnerable"
     answer.  ``tagDetection`` never sets ``funcexist`` on the no-lineage
     branch, so the verdict it just computed is overwritten with
     ``X (No vul func)`` for every tag; ``tagCombination`` then folds every
     ``X (...)`` marker into ``Safe`` through a ``defaultdict``.  Together a
     function whose lineage came out empty was published as all-versions-safe,
     indistinguishable from a real result.  Verdicts are now kept, and a CVE
     with no successful evaluation is recorded as unanalysable instead of safe.
  10. ``getFile`` requires a function to contain the *whole* hunk, git's three
     context lines included, before it will extract the function pair.  A patch
     touching a function's first line therefore falls outside it, and a hunk
     spanning two functions falls outside both - on cJSON that silently dropped
     4 of 9 CVEs before any analysis ran.  A hunk is now attributed to the
     function containing the lines it actually changes, which also lets one
     hunk contribute to both functions it straddles.
 11. The collector downloads ``<commit>.diff`` over HTTP and suppresses every
     exception. It now resolves the commit and creates the diff from the local
     clone, with a JSONL outcome for every candidate.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, NamedTuple, Sequence

# Which function a hunk belongs to is decided from the lines it actually
# changes, not from the hunk's span. Injected rather than imported because
# 2_clovery.py needs it before any of our own modules are on its path.
CHANGED_LINES_HELPER = '''

def changed_old_lines(hunk_body, start_line):
    """Old-file line numbers a hunk actually changes.

    A ``+`` line is attributed to the old line it is inserted before, so a pure
    addition still lands inside the function it was added to. ``\\`` lines
    ("No newline at end of file") carry no position.

    The text following the closing ``@@`` on the header line is git's function
    context, not hunk content, so the first split element is skipped.
    """
    lines = []
    current = start_line
    for line in hunk_body.split('\\n')[1:]:
        if line.startswith('+'):
            lines.append(current)
        elif line.startswith('-'):
            lines.append(current)
            current += 1
        elif line.startswith('\\\\'):
            continue
        else:
            current += 1
    return lines

'''

YIELD_ANCHOR = (
    "            mergetargetDepen(cpg_fileName, added_lines, removed_lines, cleaned_depen_code)\n"
    "            print('Complete cleanDepen')"
)
OLD_YIELD_BLOCK = (
    YIELD_ANCHOR
    + "\n"
    + "            # This function is finished and recorded, so it is the one\n"
    + "            # moment where stopping costs nothing: the rerun skips it.\n"
    + "            # Nothing here ever closes a Joern project, so the server\n"
    + "            # accumulates one per function for as long as it lives; ask\n"
    + "            # for a fresh one before that turns into a slow one.\n"
    + "            _reason = _resil.recycle_reason()\n"
    + "            if _reason:\n"
    + '                print(f"Yielding for a clean Joern: {_reason}", flush=True)\n'
    + "                sys.exit(_resil.RECYCLE_EXIT)"
)
NEW_YIELD_BLOCK = (
    YIELD_ANCHOR
    + "\n"
    + "            # The merged result is durable, so a rerun skips this pair.\n"
    + "            # Count the completion and yield before the long-lived Scala\n"
    + "            # compiler accumulates enough hidden state to become unstable.\n"
    + "            _reason = _resil.recycle_reason()\n"
    + "            if _reason:\n"
    + '                print(f"Yielding for a clean Joern: {_reason}", flush=True)\n'
    + "                sys.exit(_resil.RECYCLE_EXIT)"
)

EDITS: dict[str, list[tuple[str, str, str]]] = {
    "cpgqls_client/client.py": [
        (
            'query timeout',
            '    def execute(self, query):\n        return self._loop.run_until_complete(self._send_query(query))',
            '    def execute(self, query):\n        # Disabling keepalive (see connect) removes the only bound on how long\n        # a query may block, so a wedged server would hang the pipeline for\n        # ever. Fail loudly instead; CLOVERY_QUERY_TIMEOUT tunes it.\n        import os as _os\n        _timeout = float(_os.environ.get("CLOVERY_QUERY_TIMEOUT", "1800"))\n        return self._loop.run_until_complete(\n            asyncio.wait_for(self._send_query(query), timeout=_timeout)\n        )',
        ),
        (
            'websocket keepalive',
            '    def connect(self, endpoint):\n        self._ws_conn = websockets.connect(endpoint)\n        return self._ws_conn',
            '    def connect(self, endpoint):\n        # websockets >= 10 enforces ping_interval=20s / ping_timeout=20s by\n        # default. This socket only waits for Joern to signal that a query\n        # finished, and a single CPG/dataflow query on a large function blocks\n        # the server well past 20s, so keepalive tears the connection down with\n        # 1011 mid-analysis. The HTTP result fetch is the real completion\n        # signal; disable keepalive instead.\n        self._ws_conn = websockets.connect(endpoint, ping_interval=None)\n        return self._ws_conn',
        ),
    ],
    "1_cve_collector.py": [
        (
            "audited local collector import",
            "import threading\nimport argparse",
            "import threading\nimport argparse\nimport clovery_collector as _collector",
        ),
        (
            "ctags path",
            'ctagsPath   = homePath + "/ctags/ctags"',
            'ctagsPath   = os.environ.get("CTAGS_PATH", "ctags")',
        ),
        (
            "test-mode CVE filter",
            """            # FOR test
            if CVEID not in ['CVE-2020-15888', 'CVE-2020-15945', 'CVE-2020-24370', 'CVE-2020-35979', 'CVE-2020-35980', 'CVE-2020-35981']:
                continue""",
            """            # Test-mode filter removed per README; scope comes from the feeds
            # placed in Evalu/data/nvd.  CLOVERY_CVE_FILTER restores a narrow run.
            _only = os.environ.get("CLOVERY_CVE_FILTER", "")
            if _only and CVEID not in {c.strip() for c in _only.split(",")}:
                continue""",
        ),
        (
            "error_log None guard",
            """        for error_log in results:
            all_errors.extend(error_log)""",
            """        for error_log in results:
            # direct_link_collection returns None; guard the original crash.
            if error_log:
                all_errors.extend(error_log)""",
        ),
        (
            "local Git diff collector",
            "def extract_diff(save_file, diff_path, pack, clone, will_be_parsed, CVE, url):",
            "def extract_diff(save_file, diff_path, pack, clone, will_be_parsed, CVE, url):\n"
            "    return _collector.extract_local_diff(\n"
            "        save_file, diff_path, pack, clone, CVE, url,\n"
            "        clone_root=clonePath,\n"
            "        status_path=os.path.join(homePath, 'collector_status.jsonl'),\n"
            "        cloning_repo=cloningRepo,\n"
            "    )",
        ),
        (
            "reset collector evidence",
            "    if args.direct:\n        # direct_link_collection()",
            "    if args.direct:\n"
            "        # Keep only the validated pass when the cycle invokes step 1 twice.\n"
            "        _collector.reset_status(os.path.join(homePath, 'collector_status.jsonl'))\n"
            "        # direct_link_collection()",
        ),
    ],
    "2_clovery.py": [
        (
            "ctags path",
            'ctagsPath = os.getcwd() + "/ctags/ctags"',
            'ctagsPath = os.environ.get("CTAGS_PATH", "ctags")',
        ),
        (
            "changed-line helper",
            "def getFile(repo):",
            CHANGED_LINES_HELPER.strip("\n") + "\n\n\ndef getFile(repo):",
        ),
        (
            "locate changed lines per hunk",
            "                        except:\n"
            '                            print("line parsing error..")\n'
            "                            continue",
            "                        except:\n"
            '                            print("line parsing error..")\n'
            "                            continue\n"
            "                        # sl..el spans the hunk *including* git's three\n"
            "                        # context lines. Requiring a function to contain\n"
            "                        # all of that drops a change on the function's own\n"
            "                        # first line (the context reaches above it) and a\n"
            "                        # hunk touching two functions (inside neither), and\n"
            "                        # the CVE then produces no function pair at all.\n"
            "                        changed_lines = changed_old_lines(\n"
            '                            finer[i + 1] if i + 1 < len(finer) else "", sl\n'
            "                        )",
        ),
        (
            "attribute hunk by changed lines",
            "                            if sl >= startline and el <= endline:",
            "                            if any(startline <= changed <= endline\n"
            "                                   for changed in changed_lines):",
        ),
    ],
    "3_clovery_cpg.py": [
        (
            "resilience module import",
            'mergePath = JresultPath + "mergeRES/"\nrepoPath = evaluPath + "/clones/"',
            'mergePath = JresultPath + "mergeRES/"\nrepoPath = evaluPath + "/clones/"\n\n'
            "# Recover from a Joern server that stops answering instead of losing the\n"
            "# step; installed next to this script by apply_compat_patch.py. Imported\n"
            "# as a module and used through it on purpose: this injected text then\n"
            "# stays byte-identical as the module gains helpers, and re-running the\n"
            "# patcher recognises it as already applied instead of adding a second\n"
            "# copy below the same anchor.\n"
            "import clovery_resilience as _resil\n\n"
            "_resil.set_ledger_dir(JresultPath)",
        ),
        (
            "skip functions abandoned to timeouts",
            '            if os.path.exists(mer_fileName):\n'
            '                print(f"Skipping already processed file: {combfname}")\n'
            "                continue",
            '            if os.path.exists(mer_fileName):\n'
            '                print(f"Skipping already processed file: {combfname}")\n'
            "                continue\n"
            "            # Hung once on a loaded server and again on a fresh one: the\n"
            "            # function is the problem, so give up on it rather than let it\n"
            "            # block every function behind it.\n"
            "            if _resil.query_timeout_exhausted(combfname):\n"
            '                print(f"Skipping function abandoned to query timeouts: {combfname}")\n'
            "                continue",
        ),
        (
            "leave the step on a lost query",
            "            oldfunc_linedic = create_cpg(repo, combfname, ext, vulFuncPath, '_OLD', 'vulRES', cpg_fileName, removed_lines)\n"
            "            newfunc_linedic = create_cpg(repo, combfname, ext, newFuncPath, '_NEW', 'patRES', cpg_fileName, added_lines)",
            "            # A query that never comes back used to kill the step and, with\n"
            "            # it, every function still queued - 812 of 866 pairs on\n"
            "            # tensorflow. Record which function it was and exit distinctly,\n"
            "            # so the cycle can restart Joern and rerun: the pairs already\n"
            "            # merged are skipped above, so the rerun resumes here.\n"
            "            try:\n"
            "                oldfunc_linedic = create_cpg(repo, combfname, ext, vulFuncPath, '_OLD', 'vulRES', cpg_fileName, removed_lines)\n"
            "                newfunc_linedic = create_cpg(repo, combfname, ext, newFuncPath, '_NEW', 'patRES', cpg_fileName, added_lines)\n"
            "            except _resil.TRANSIENT_QUERY_ERRORS as error:\n"
            "                attempts = _resil.record_query_timeout(combfname)\n"
            '                print(f"Joern stopped answering on {combfname} '
            '(attempt {attempts}): {error!r}", flush=True)\n'
            "                sys.exit(_resil.QUERY_TIMEOUT_EXIT)",
        ),
        (
            "drop the project once its two files are written",
            "            fid.write(idsres)\n    return func_linedic",
            "            fid.write(idsres)\n"
            "        # Everything downstream reads the two files just written, never\n"
            "        # this project again - each import is a single extracted function,\n"
            "        # so no other function's analysis can refer to it either. Keeping\n"
            "        # it only grows the server: upstream never closes one, and a\n"
            "        # repository the size of tensorflow imports hundreds within a\n"
            "        # single step. Dropping it here bounds the store by what is in\n"
            "        # flight rather than by how many functions have been analysed.\n"
            "        client.execute('delete(\"' + label + '\")')\n"
            "    return func_linedic",
        ),
        (
            "yield before the server gets heavy",
            YIELD_ANCHOR,
            NEW_YIELD_BLOCK,
        ),
        (
            "tag scan needs step 4's merged output",
            "            repotagPath = os.path.join(tagPath + '/' + repo + '/')\n"
            "            tagfile_path = os.path.join(repotagPath, tagfilename)",
            "            # checkVul reads the merged dependence file for this function\n"
            "            # and cannot run without it, yet the tag scan is driven by\n"
            "            # CombiPatchFunc, which still lists functions step 4 never got\n"
            "            # through - abandoned to a timeout, or dropped by create_cpg's\n"
            "            # early return on an empty Joern result. Either way the scan\n"
            "            # died with FileNotFoundError, taking every remaining function\n"
            "            # with it. A function that did not survive step 4 leaves the\n"
            "            # pipeline here instead.\n"
            "            if not os.path.exists(mergePath + cpg_fileName.replace('_cpg.txt', '_merged_DEP.json')):\n"
            '                print(f"Skipping function with no merged CPG: {combfname}")\n'
            "                continue\n"
            "            repotagPath = os.path.join(tagPath + '/' + repo + '/')\n"
            "            tagfile_path = os.path.join(repotagPath, tagfilename)",
        ),
        (
            'record_file_time KeyError',
            '        step_file_time_data[step_name][repo][file_name] += duration',
            '        # `+=` on a key that was never initialised: every file in step 5\n        # raised KeyError *after* its Lineage was written, so the work was\n        # done but reported as an error.\n        step_file_time_data[step_name][repo][file_name] = (\n            step_file_time_data[step_name][repo].get(file_name, 0) + duration\n        )',
        ),
        (
            "ctags path",
            'ctagsPath = os.getcwd() + "/ctags/ctags"',
            'ctagsPath = os.environ.get("CTAGS_PATH", "ctags")',
        ),
        (
            "safeTagCombiPath definition",
            'tagCombiPath = evaluPath + "/tagCombi/"',
            'tagCombiPath = evaluPath + "/tagCombi/"\n'
            "# CVEs whose every tag came back Safe are separated out; upstream\n"
            "# references this path without ever defining it.\n"
            'safeTagCombiPath = evaluPath + "/tagCombi_allSafe/"',
        ),
        (
            "Joern call-id query",
            """            query = 'cpg.method("' + func + '").call.l'  """,
            """            # Older Joern rendered `id = <n>L` inside each Call(...) block;
            # current builds omit it, so ask for "<id>,<lineNumber>" pairs.
            query = ('cpg.method("' + func
                     + '").call.map(c => c.id + "," + c.lineNumber.getOrElse(-1)).l')""",
        ),
        (
            "Joern call-id parser",
            """        match_nodedic = {}
        for call in ibody.split('Call(')[1:]:
            line_str = call.split('lineNumber = Some(value = ')[1].split(')')[0]
            call_lineNum = int(line_str)
            call_nodeid = call.split('id = ')[1].split('L')[0]
            if call_lineNum not in match_nodedic:
                match_nodedic[call_lineNum] = []
            match_nodedic[call_lineNum].append(call_nodeid)""",
            """        match_nodedic = {}
        # Query emits "<nodeId>,<lineNumber>" strings; -1 means no line number.
        for node_id_str, line_str in re.findall(r'"(\\d+),(-?\\d+)"', ibody):
            call_lineNum = int(line_str)
            if call_lineNum < 0:
                continue
            if call_lineNum not in match_nodedic:
                match_nodedic[call_lineNum] = []
            match_nodedic[call_lineNum].append(node_id_str)""",
        ),
        (
            "checkTag repo NameError",
            '        file_path = os.path.join(step_folder_path, f"{step_name}_{repo}.json")',
            "        # `repo` is tagDetection's loop variable, not in scope here; the\n"
            "        # timing file covers the whole step.\n"
            '        file_path = os.path.join(step_folder_path, f"{step_name}.json")',
        ),
        (
            "no-lineage tag verdict discarded",
            "                        whether = checkVul(funcBody, cpg_fileName)\n"
            "                        taglist[tag] = whether",
            "                        # Count the function as found only when it really\n"
            "                        # was. Upstream never sets funcexist on this branch,\n"
            "                        # so the post-loop `elif not funcexist` overwrote the\n"
            "                        # verdict just computed with \"X (No vul func)\" for\n"
            "                        # every tag - and tagCombination reads that as Safe.\n"
            "                        # A function whose lineage came out empty was\n"
            "                        # therefore always published as all-versions-safe.\n"
            "                        if funcBody:\n"
            "                            whether = checkVul(funcBody, cpg_fileName)\n"
            "                            taglist[tag] = whether\n"
            "                            funcexist = True",
        ),
        (
            "unextracted tag counted as safe",
            '            combined_results = defaultdict(lambda: "Safe")\n'
            "            all_safe = True",
            "            # A tag whose function could not be extracted is Unknown, not\n"
            '            # Safe. The defaultdict folded every "X (...)" marker into Safe,\n'
            "            # so a CVE with zero successful evaluations was published as\n"
            "            # all-versions-safe - indistinguishable from a real result.\n"
            "            combined_results = {}\n"
            "            all_safe = True\n"
            "            evaluated = False",
        ),
        (
            "merge unknown separately",
            "                    for version, status in data.items():\n"
            '                        if status == "Vulnerable":\n'
            '                            combined_results[version] = "Vulnerable"\n'
            "                            all_safe = False\n"
            "                        else:\n"
            "                            combined_results[version] = "
            'combined_results.get(version, "Safe")',
            "                    for version, status in data.items():\n"
            '                        if status == "Vulnerable":\n'
            '                            combined_results[version] = "Vulnerable"\n'
            "                            evaluated = True\n"
            '                        elif status == "Safe":\n'
            "                            evaluated = True\n"
            '                            if combined_results.get(version) != "Vulnerable":\n'
            '                                combined_results[version] = "Safe"\n'
            "                        else:\n"
            '                            combined_results.setdefault(version, "Unknown")',
        ),
        (
            "suppress result with no evaluation",
            "            if combined_results:",
            "            all_safe = bool(combined_results) and all(\n"
            '                status == "Safe" for status in combined_results.values()\n'
            "            )\n"
            "            if not evaluated:\n"
            "                # Not one function of this CVE produced a verdict; writing a\n"
            "                # result file would claim an analysis that never happened.\n"
            "                unable_tag_extract_set.add(cve)\n"
            "\n"
            "            if combined_results and evaluated:",
        ),
    ],
}


# --------------------------------------------------------------------------- lean
# The paper (Sect. 4) only needs two git reads per target function:
#
#     git log --follow --diff-filter=AMD --name-status ... -- <file path>
#     git log -1 <commit id> -L:<function name>:<path>
#
# The implementation goes much further: it runs `git checkout -f` for every
# commit in the function history *and every tag* before reading the file off the
# working tree.  On rsyslog (512 tags) that is 512 full-tree checkouts of a repo
# that only ever gets one file read out of it.
#
# Every one of those reads can be served by `git show <rev>:<path>` instead, so
# the working tree is never needed.  That in turn allows the clone to be
# blobless and checkout-free, which is what "work from diffs, not a full clone"
# means in practice: only the blobs actually inspected are ever fetched.
#
# That replacement logic is clovery_lean.py, installed into the checkout as a
# module; only the import below is injected.
LEAN_MODULE = "clovery_lean.py"

# Restarting Joern and rerunning the step is the cycle's job; knowing which
# function was lost and when to stop retrying it is this module's.
RESILIENCE_MODULE = "clovery_resilience.py"

# Local git diff extraction plus an auditable per-candidate status ledger.
COLLECTOR_MODULE = "clovery_collector.py"

LEAN_IMPORT = """\
# Blob reads with no working tree; installed next to this script by
# apply_compat_patch.py.  Clovery runs each step from its own directory, so
# that directory is sys.path[0] and a plain import resolves.
from clovery_lean import materialize_blob, prefetch_blobs, set_scratch_dir

set_scratch_dir(Garbage)"""

# An earlier version of this script injected the same helpers as source text.
# A checkout patched by it still carries that copy, which the import would
# leave behind as dead duplicate code, so it is removed first.
LEGACY_HELPER_START = "def _lean_blob_dir():"
LEGACY_HELPER_END = "def checkout_cmd(branch):"

LEAN_EDITS: dict[str, list[tuple[str, str, str]]] = {
    "2_clovery.py": [
        (
            'blob ids -> commit:path',
            '                        vulfile = "vulfile." + ext\n                        command = "git show " + oldIdx + " > " + vulfile\n                        patfile = "patfile." + ext\n                        command_pat = "git show " + newIdx + " > " + patfile',
            '                        vulfile = "vulfile." + ext\n                        patfile = "patfile." + ext\n                        # The diff header carries *abbreviated* blob ids. A blobless\n                        # clone has none of those objects locally, so git cannot even\n                        # expand the abbreviation. commit^:<path> and commit:<path>\n                        # name the same two blobs and fetch them on demand.\n                        _old_rel = oldPath[2:] if oldPath.startswith("a/") else oldPath\n                        _new_rel = newPath[2:] if newPath.startswith("b/") else newPath\n                        command = \'git show "%s^:%s" > %s\' % (Commit_id, _old_rel, vulfile)\n                        command_pat = \'git show "%s:%s" > %s\' % (Commit_id, _new_rel, patfile)',
        ),
    ],
    "1_cve_collector.py": [
        (
            "blobless, checkout-free clone",
            """    if not clone.startswith('git clone'):
        clone = 'git clone ' + clone
    elif clone.startswith('git clonegit'):
        clone = clone.replace('git clonegit', 'git clone git')""",
            """    if not clone.startswith('git clone'):
        clone = 'git clone ' + clone
    elif clone.startswith('git clonegit'):
        clone = clone.replace('git clonegit', 'git clone git')

    # Nothing downstream reads the working tree once the lean patches are in,
    # and full history is still required for `git log --follow` and tags, so
    # fetch commits/trees but leave blobs on the server until asked for.
    if os.environ.get("CLOVERY_LEAN_CLONE", "1") not in ("0", "false", ""):
        if clone.startswith('git clone ') and '--filter=' not in clone:
            clone = clone.replace(
                'git clone ', 'git clone --filter=blob:none --no-checkout ', 1
            )""",
        ),
    ],
    "3_clovery_cpg.py": [
        (
            'batch blob prefetch',
            '            for tag in tags:\n                fileexist = False \n                funcexist = False',
            '            # One batched resolve beats one promisor fetch per tag.\n            prefetch_blobs(tags, [p for _, p in checkname] if logexist else [fPath])\n            for tag in tags:\n                fileexist = False \n                funcexist = False',
        ),
        (
            "lean module import",
            "def checkout_cmd(branch):",
            LEAN_IMPORT + "\n\n\ndef checkout_cmd(branch):",
        ),
        (
            'function history without checkout',
            '    try:\n        checkoutCommand = f"git checkout -f {commitID}"\n        astString = subprocess.check_output(r\'{}\'.format(checkoutCommand), stderr=subprocess.STDOUT, shell=True).decode(errors=\'ignore\')\n    except:\n        checkouterror_cmd = "rm -f .git/index.lock" \n        HEADlock_cmd = "rm -f .git/HEAD.lock"\n        subprocess.check_output(checkouterror_cmd, stderr=subprocess.STDOUT, shell=True).decode()\n        subprocess.check_output(HEADlock_cmd, stderr=subprocess.STDOUT, shell=True).decode()\n\n    original_file_path = os.path.join(repoPath, repo, filepath)\n    cfile = "ctags." + ext',
            '    # Read the file at this commit directly instead of checking the tree out.\n    original_file_path = materialize_blob(commitID, filepath)\n    if original_file_path is None:\n        return commit_fname, ""\n    cfile = "ctags_%d.%s" % (os.getpid(), ext)',
        ),
        (
            'tag scan without checkout',
            '                            subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)\n                            fileexist = True  \n                            searchPath = repoPath + repo + \'/\' + logfpath\n                            if not os.path.exists(searchPath):\n                                fileexist = False\n                                continue\n                            checkout_cmd(tag)\n                            ctags_cmd = \'"\' + ctagsPath + \'" -f - --kinds-C=* --fields=neKSt "\' + repoPath + repo + \'/\' + logfpath + \'"\'',
            '                            searchPath = materialize_blob(tag, logfpath)\n                            if searchPath is None:\n                                fileexist = False\n                                continue\n                            fileexist = True\n                            ctags_cmd = \'"\' + ctagsPath + \'" -f - --kinds-C=* --fields=neKSt "\' + searchPath + \'"\'',
        ),
        (
            'tag scan fallback without checkout',
            '                        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)\n                        fileexist = True  \n                        checkout_cmd(tag)\n                        ctags_cmd = \'"\' + ctagsPath + \'" -f - --kinds-C=* --fields=neKSt "\' + repoPath + repo + \'/\' + fPath + \'"\'',
            '                        searchPath = materialize_blob(tag, fPath)\n                        if searchPath is None:\n                            fileexist = False\n                            continue\n                        fileexist = True\n                        ctags_cmd = \'"\' + ctagsPath + \'" -f - --kinds-C=* --fields=neKSt "\' + searchPath + \'"\'',
        ),
        (
            'tag scan fallback path',
            "                        searchPath = repoPath + repo + '/' + fPath\n                        funcBody, exit = getOldFuncs(searchPath, fName, ctags_res)",
            '                        # searchPath is the materialized blob\n                        funcBody, exit = getOldFuncs(searchPath, fName, ctags_res)',
        ),
        (
            "git log needs no checkout",
            """        lates = subprocess.check_output(lates_branch_cmd, stderr=subprocess.STDOUT, shell=True).decode("UTF-8")
        checkout_cmd(lates)
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode("UTF-8")""",
            """        # `git log -- <path>` reads history, not the working tree.
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode("UTF-8")""",
        ),
        (
            "git tag needs no checkout",
            """                lates = subprocess.check_output(lates_branch_cmd, stderr=subprocess.STDOUT, shell=True).decode("UTF-8")
                checkout_cmd(lates)
                tagDate_res = subprocess.check_output(tagDate_cmd, stderr=subprocess.STDOUT, shell=True).decode()""",
            """                # `git tag` lists refs; no checkout required.
                tagDate_res = subprocess.check_output(tagDate_cmd, stderr=subprocess.STDOUT, shell=True).decode()""",
        ),
    ],
}


def strip_legacy_helper(text: str) -> tuple[str, bool]:
    """Drop the lean helpers an earlier version of this script inlined.

    Bounded by two markers rather than matched as a literal, so a checkout
    patched by any of those versions is recognised.  Must run before the import
    is inserted - afterwards the import block sits inside these bounds.
    """

    start = text.find(LEGACY_HELPER_START)
    if start < 0:
        return text, False
    end = text.find(LEGACY_HELPER_END, start)
    if end < 0:
        return text, False
    return text[:start] + text[end:], True


def migrate_resilience_yield(text: str) -> tuple[str, bool]:
    """Update the older project-count-only yield block without duplicating it."""
    if OLD_YIELD_BLOCK not in text:
        return text, False
    return text.replace(OLD_YIELD_BLOCK, NEW_YIELD_BLOCK, 1), True


class PatchResult(NamedTuple):
    applied: int
    already: int
    missing: int


ALREADY_MARKERS = {
    # A later optimisation moved this once-per-function block into repo_tags(),
    # while preserving the no-checkout implementation.
    "git tag needs no checkout": "# `git tag` lists refs; no checkout required.",
}


def patch_file(
    path: Path,
    edits: Sequence[tuple[str, str, str]],
    *,
    migrate: Callable[[str], tuple[str, bool]] | None = None,
) -> PatchResult:
    raw = path.read_bytes().decode("utf-8", errors="surrogateescape")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    changed = False
    if migrate is not None:
        text, migrated = migrate(text)
        if migrated:
            print("    ~ migrated legacy compatibility block")
            changed = True

    applied = already = missing = 0
    for label, old, new in edits:
        if new in text or ALREADY_MARKERS.get(label, "\0") in text:
            print(f"    - {label}: already applied")
            already += 1
            continue
        if old not in text:
            print(f"    ! {label}: anchor not found (upstream changed?)", file=sys.stderr)
            missing += 1
            continue
        text = text.replace(old, new, 1)
        print(f"    + {label}")
        applied += 1
        changed = True

    if changed:
        out = text.replace("\n", "\r\n") if crlf else text
        path.write_bytes(out.encode("utf-8", errors="surrogateescape"))
    return PatchResult(applied, already, missing)


def install_module(clovery: Path, name: str) -> bool:
    """Copy a helper module into the checkout so the injected import resolves.

    A copy rather than a symlink or a sys.path entry: the checkout is routinely
    thrown away and re-cloned, and the cycle purges only Evalu/, so the copy
    survives exactly as long as the patched scripts it belongs to.
    """

    source = Path(__file__).resolve().parent / name
    if not source.is_file():
        print(f"error: missing {source}", file=sys.stderr)
        return False
    target = clovery / name
    payload = source.read_bytes()
    if target.is_file() and target.read_bytes() == payload:
        print(f"{name}:\n    - already installed")
        return True
    target.write_bytes(payload)
    print(f"{name}:\n    + installed")
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Patch a Clovery checkout for a current toolchain")
    parser.add_argument(
        "--clovery",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "clovery",
        help="path to the Clovery checkout (default: <repo>/clovery)",
    )
    parser.add_argument(
        "--no-lean",
        dest="lean",
        action="store_false",
        default=True,
        help="keep upstream's full clone + per-tag checkout behaviour",
    )
    args = parser.parse_args(argv)

    if not (args.clovery / "1_cve_collector.py").exists():
        print(f"error: not a Clovery checkout: {args.clovery}", file=sys.stderr)
        return 1

    groups: dict[str, list[tuple[str, str, str]]] = {
        name: list(edits) for name, edits in EDITS.items()
    }
    # Timeout recovery is not a lean-mode concern: the server can stop answering
    # whichever way the clone was made.
    if not install_module(args.clovery, RESILIENCE_MODULE):
        return 1
    if not install_module(args.clovery, COLLECTOR_MODULE):
        return 1
    if args.lean:
        for name, edits in LEAN_EDITS.items():
            groups.setdefault(name, []).extend(edits)
        if not install_module(args.clovery, LEAN_MODULE):
            return 1

    total_applied = total_missing = 0
    for name, edits in groups.items():
        target = args.clovery / name
        if not target.exists():
            print(f"error: missing {target}", file=sys.stderr)
            return 1
        print(f"{name}:")
        migrate = None
        if name == "3_clovery_cpg.py":
            # Timeout resilience is independent of lean mode. An older patched
            # checkout already contains a complete yield block, so migrate it
            # before exact replacement or the anchor prefix would be duplicated.
            def migrate(text: str) -> tuple[str, bool]:
                text, resilience_changed = migrate_resilience_yield(text)
                lean_changed = False
                # Only in lean mode: with --no-lean the inlined helper is still
                # what old call sites resolve against, so removing it would break
                # the checkout rather than tidy it.
                if args.lean:
                    text, lean_changed = strip_legacy_helper(text)
                return text, resilience_changed or lean_changed
        result = patch_file(target, edits, migrate=migrate)
        total_applied += result.applied
        total_missing += result.missing

    if total_missing:
        print(
            f"\nerror: {total_missing} edit(s) could not be applied to {args.clovery}. "
            f"The checkout would run with those fixes missing; re-check the anchors "
            f"against the upstream revision before using it.",
            file=sys.stderr,
        )
        return 1

    print(f"\n{total_applied} edit(s) applied to {args.clovery}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
