# Clovery pipeline

Pins exact vulnerable/fixed versions for the C corpus so the results can be
handed to the SBOM database, using [Clovery](https://github.com/kimdu0/clovery)
plus the applicability DB built by `scripts.nvd_normalization`.

```
scripts/clovery/
  apply_compat_patch.py        make an upstream Clovery checkout runnable here
  clovery_lean.py              git blob reads with no working tree (installed
                               into the checkout by the patcher)
  clovery_resilience.py        survive a Joern server that stops answering
                               (installed into the checkout by the patcher)
  nvd2_to_clovery_feed.py      NVD 2.0 -> the retired 1.1 feed Clovery reads
  recover_patch_commits.py     patch commits NVD never referenced (OSV + git log)
  fixed_version_from_commit.py fixed version per release series, from patch commits
  verify_version_range.py      validate the published range, propose the corrected one
  clovery_cycle.py             clone -> analyse -> harvest -> purge, one repo at a time
```

## Why each piece exists

**`apply_compat_patch.py`** - upstream does not run as-is. It hard-codes six
test CVEs, hard-codes a `ctags` path that does not exist (which silently breaks
step 5, since the failure lands in a bare `except` and leaves `old_astString`
unbound), crashes on `all_errors.extend(None)`, has two `NameError`s at the tail
of steps 6 and 7, and parses `id = <n>L` out of Joern's `Call(...)` rendering -
a field current Joern no longer emits, so step 4 dies with `IndexError`.

One more library drift bites only on large projects: `cpgqls_client` opens its
websocket with defaults, and modern `websockets` enforces a 20 s keepalive ping
timeout. A single CPG or dataflow query on a large function blocks the Joern
server far longer, so the client kills the connection with
`1011 keepalive ping timeout` part-way through step 4. Keepalive is disabled -
completion is signalled by the HTTP result fetch, not by pings.

The patcher applies all of it by string replacement, preserves CRLF, and is
idempotent. An edit whose anchor is missing **fails the run** (non-zero exit):
each of these fixes stands between the pipeline and a crash or a wrong result,
so a checkout that silently lost one is worse than no checkout at all.

Only the fixes themselves are injected as text. The lean-mode logic is
`clovery_lean.py`, a real module the patcher copies into the checkout - so it
is lintable, testable, and reviewable as code rather than as a string literal.
The patch inserts one import and one `set_scratch_dir(Garbage)` call. A
checkout patched by an earlier version, which inlined those helpers, has the
inlined copy removed on the next run; both paths converge on the same file.

**`clovery_resilience.py`** - step 4 runs four queries per function against a
long-lived Joern server, and the server can simply stop answering. On tensorflow
that happened to a *millisecond-scale* id lookup, right after the three
expensive queries on the same 78-line function had returned; with keepalive
disabled the query timeout is the only bound, so it hung for the full 1800 s.
Upstream lets the exception escape and the step dies with it - 812 of 866
function pairs' worth of work discarded, and a rerun meets the same function
again.

Three mechanisms, in order of how much they are relied on:

| | what it does | when |
|---|---|---|
| leave the step | record the function, exit `42` | a query never came back |
| yield the server | exit `43` while everything is still healthy | completed pairs reach `--max-joern-functions` (or a project/RSS safety limit) |
| give up on one function | skip it permanently | it hung again on a fresh server |

All three are affordable only because resuming is: a function already merged is
skipped on the way back in, so rerunning step 4 costs nothing for work already
done. That is what turns "the server died" from a lost repository into a pause.

The second row is the one that answers "what stops this happening again".
`create_cpg` deletes completed projects, but ImageMagick showed that Joern's
long-lived Scala compiler can still overflow a worker thread's stack while the
workspace stays nearly empty. The step therefore counts completed function
pairs and restarts after 100 by default. Project count remains a safety net for
an import interrupted before deletion, and RSS can be enabled as another one.
The step stops on its own terms at the one moment where stopping is free.

The distinction between exit 42 and exit 43 is budgeted, not cosmetic: a healthy
yield is expected several times on a large repository. `--max-recycles` provides
a floor of 20, and step 4 raises that budget from its pending function count and
observed progress, so a 3,324-function repository cannot fail merely because it
needs 33 planned restarts. A healthy yield that creates no durable merged result
is rejected as a no-progress loop. A server that stops answering *again* after a
restart uses the separate `--step-retries` budget (default 5).

Underneath all three, `create_cpg` now drops each project once the two files it
produces have been written. Nothing downstream reads a project again - the
dependence analysis, the merge and the tag scan all work from the dumped
`_cpg.txt` / `_ids.txt` - and each import is a *single extracted function*, so no
other function's analysis can refer to it either. Measured over 40 imports of the
same function against a freshly started server:

| | projects held | resident | wall |
|---|---|---|---|
| upstream, keep | 40 | 616 -> 1059 MB | 98.9 s |
| `delete` per function | **0** | 628 -> 938 MB | 101.2 s |

So the store is bounded outright and the cost is ~2%. Resident memory is *not*
bounded: it grows more slowly (+310 MB against +443 MB) but the JVM does not give
the heap back. That is the reason the threshold yield above exists rather than
being made redundant by this - dropping projects makes the server last longer,
restarting it is what actually resets it.

A function abandoned this way leaves the pipeline rather than poisoning it: the
tag scan is driven by `CombiPatchFunc`, which still lists it, so it now checks
for step 4's merged output first. Without that the scan died with
`FileNotFoundError` and took every remaining function with it - reachable
upstream too, through `create_cpg`'s early return on an empty Joern result.
Abandoned functions are named in the run output and in `summary.json`, never
just counted.

**`nvd2_to_clovery_feed.py`** - Clovery reads `nvdcve-1.1-<year>.json`, but NIST
retired the 1.1 feeds. This reproduces the four paths Clovery actually touches
(`CVE_data_meta.ID`, `problemtype`, `references.reference_data[].url`,
`impact.baseMetricV2.cvssV2.baseScore`). `clovery_cycle.py plan` reuses its
`to_v11_item` to emit per-repo feeds; the standalone CLI is for converting whole
years from `nvd-json-2.0/` outside the DB-driven flow.

### Where targets come from

`plan` is driven by the applicability DB, not by scanning NVD:

```
corpus repo (owner@name)
  -> product_entity            exact (vendor,product), then <name>_project
  -> identity_cluster          strict accepted members merged in
  -> current_binding           the CVEs the DB actually binds
  -> raw_cve.byte_offset       seek those records out of the source JSONL
  -> references                keep git-host commit URLs for *this* repo
```

The DB has no reference-URL table, and Clovery needs the patch commit, so the
last two steps go back to the snapshot the DB indexes - but only for the CVEs
already selected, seeked by offset rather than re-parsing the corpus.

Those offsets belong to one exact snapshot, so a file merely sitting at the
recorded path is not good enough: refreshing the corpus shifts every offset past
the first changed record, the seek lands mid-record, and the JSON fails to parse.
Nothing said so - the record was skipped and the CVE quietly went missing, which
is how recovery came to contribute **nothing at all** while still reporting
success. The manifest's `byte_size` is now checked against each candidate; `plan`
refuses to build on a mismatch, and `run` stops that repository rather than
analysing an unvalidated partial feed.

Restricting to commit URLs belonging to the same repository matters: a CVE
routinely references advisories, forks and PoC repos, and only a commit in this
repository can be turned into its patch functions.

**`recover_patch_commits.py`** - Clovery needs a patch commit, and NVD usually
does not give one. Of the 124 CVEs the DB binds to Exiv2, only 10 reference a
commit: 77 link an issue or advisory instead, and 37 carry no git link at all.
Two recovery paths close most of that gap:

| source | how | Exiv2 |
|---|---|---|
| OSV | `affected[].ranges` of `type: GIT`, `fixed: <sha>` events. Public API, no auth. | +14 |
| commit message | `git log --all --no-merges --grep <CVE>` in the clone. No network. | +9 |

They complement rather than overlap - OSV covered the 2021-2025 CVEs, the commit
search the 2017-2019 ones. Together the analysable set went **10 -> 33**.

Three filters are load-bearing on the commit search: merges carry no diff of
their own, "add a reproducer for CVE-x" commits match the message but only touch
`test/`, `fuzz/` or `samples/`, and branch-sync squash commits copy unrelated
CVE-bearing child messages into a huge body. A commit must change non-test
C/C++ source, standard `Revert "Fix CVE-..."` subjects are rejected, and a CVE
named by the commit's own subject outranks one found only in a sync/release
body. Ranking happens before the three-candidate cap, so a newer roll-up cannot
hide the actual patch farther down the history.

OSV `last_affected` describes a vulnerable boundary, not a patch, so it is never
used to widen the target plan or fed to Clovery. The plan uses only matching
`fixed` events: direct NVD's 443 repositories union OSV's 572 repositories is
the current **605-repository upper bound**.

Recovery and validation run **after step 1**, because the commit search needs
the clone. The first collector pass only bootstraps that clone. Every direct,
git-log and OSV candidate is then resolved in the local repository and classified:
wrong/malformed URL, missing commit, docs or unsupported language, test-only,
version boundary, or accepted non-test `.c/.cc/.cpp` patch. Converted OSV
`fixed` boundaries require both a supported source diff and the CVE in the commit
message. The run feed is atomically replaced with accepted candidates, bootstrap
diffs are discarded, and step 1 reruns from that validated feed.

Diffs are generated by local `git show`, not by scraping `<url>.diff`; HTTP
errors can no longer disappear into a bare `except`. The candidate decision is
kept in `patch_evidence.json` and the collector decision in
`collector_status.jsonl`. Control recovery with
`--recover {none,gitlog,osv,both}` (default `both`); `none` still validates direct
references.

**`fixed_version_from_commit.py`** - when a CVE reference points at the patch
commit, the release boundary is already in the repository and does not need code
analysis. Reading it correctly is subtle: GitHub shows a *range* of containing
tags (`7.1.2-29 … 7.0.4-4`), where only the oldest is the fixed version, and a
project with parallel release series has one boundary per series. So:

```
patch commit -> git tag --contains -> drop rc/beta/archive refs
             -> split by series -> earliest tag per series
             -> assert the preceding release does NOT contain it
```

**`verify_version_range.py`** - follows Clovery's own `verifyCPE` design
(`3_clovery_cpg.py:1461-1830`): normalise the tags, collapse the per-tag verdicts
into contiguous ranges, then compare start / end / middle against the published
range. Two changes: the published range is read from the applicability DB
(`version_segment`) rather than a dumped CPE file, since that is what we are
correcting; and the comparison feeds a *proposed* range instead of only flagging
a discrepancy.

Two upstream bugs are deliberately not carried over - `compare_CPE` compares
versions with plain string `<` (so `1.10` sorts before `1.9`), and
`extract_vulnerable_ranges` closes a run mixing raw and numeric spellings. Both
go through `version_key` here.

Confidence comes from agreement between independent signals:

| confidence | meaning |
|---|---|
| `high` | the release after Clovery's last vulnerable tag *is* the commit-derived fixed version |
| `medium` | only one signal produced a boundary, over full tag coverage |
| `low` | the two disagree (`fixed_conflict` records both), or the range rests on partial tag coverage |

Two disagreements count. The obvious one is two different fixed versions. The
other is a range that stays vulnerable through a release which already contains
the patch commit - `last_affected >= fixed` is self-contradictory, so one of the
signals is wrong and the proposal is not offered as if it were single-sourced.

Coverage is reported per CVE as `evaluated_tags` / `tag_count`. A tag whose
function could not be extracted is `Unknown`, never `Safe`: it neither closes a
vulnerable run nor counts as evidence of safety. A range built where some tags
are `Unknown` cannot exceed `low` unless the patch commit corroborates it -
missing tags do not weaken a boundary two independent signals already agree on.

### Working from diffs instead of full clones

The paper (Sect. 4) needs exactly two git reads per target function:

```
git log --follow --diff-filter=AMD --name-status --pretty=format:"%H %ci" -- <file>
git log -1 <commit id> -L:<function name>:<path>
```

The implementation does far more: `getFuncCode` runs `git checkout -f` for every
commit in the function history, and `tagDetection` runs one for **every tag**
before reading the file off the working tree - 512 full-tree checkouts on
rsyslog, for a repository from which exactly one file is ever read.

Every one of those reads is served by `git show <rev>:<path>` instead, so the
working tree is never needed and the clone can be
`--filter=blob:none --no-checkout`. One consequence had to be handled: the diff
header's `index 1733811..c9c5b61` are *abbreviated blob ids*, and a blobless
clone cannot even expand the abbreviation because the objects are not local, so
step 2 now addresses the same blobs as `<commit>^:<path>` / `<commit>:<path>`.

Both modes produce identical results. Measured on cJSON (2 CVE, 49 tags):

| mode | clone | wall time |
|---|---|---|
| `--full-clone` | 4.9 MB | 77 s |
| lean (default) | 2.5 MB | 305 s |

The trade is disk for network: in a blobless clone every historical file read is
a promisor fetch. On cJSON that is a clear loss; it pays off where disk is the
binding constraint (tensorflow is ~1.3 GB cloned in full, FFmpeg ~0.47 GB).
Batching the tag-scan reads through `git cat-file --batch-check` did not move the
number, which locates the remaining cost in step 5's per-commit fetches rather
than the tag scan.

Use `--full-clone` on small repositories, the default on large ones.

**`clovery_cycle.py`** - Clovery accumulates every clone and intermediate under
`Evalu/`, so a corpus-wide run would need hundreds of GB at once. The cycle keeps
peak disk to one repository, and is resumable. It runs the fixed-version and
range-verification stages automatically.

## Running it

```bash
# once: make the checkout runnable
python scripts/clovery/apply_compat_patch.py --clovery ../clovery

# build the 605-repository direct+OSV upper-bound plan
python scripts/clovery/clovery_cycle.py plan \
  --clovery ../clovery \
  --source-jsonl data/nvd-cves.current.jsonl \
  --osv-dir data/osv

# Joern must be served FROM the clovery directory, or its workspace/ won't resolve
cd clovery && joern --server --server-host localhost --server-port 8080 \
    --server-auth-username username --server-auth-password password &

# run; resumable, so Ctrl-C and re-run to continue
python scripts/clovery/clovery_cycle.py run --limit 20

# also redo results produced before patch_evidence.json existed
python scripts/clovery/clovery_cycle.py run --revalidate-legacy

python scripts/clovery/clovery_cycle.py status -v
```

Useful `run` flags: `--only owner@repo`, `--max-clone-gb` (skip oversized
repositories), `--retry-failed`, `--step-timeout`, `--full-clone`,
`--series-depth 2` (treat `major.minor` as the release series),
`--revalidate-legacy`, `--rerun-done --only owner@repo`, and
`--python` / `--ctags` to select binaries.

Joern's health is governed by four more, all of which need `--joern-cmd` so the
cycle is actually able to restart the server:

| flag | default | what it bounds |
|---|---|---|
| `--max-joern-projects` | 400 | store size before the step yields for a fresh server (0 disables) |
| `--max-joern-rss-mb` | 0 (off) | the same, on resident memory |
| `--max-cpg-pairs` | 5000 | refuse an anomalous step-4 workload before Joern starts (0 disables) |
| `--max-recycles` | 20 | minimum healthy-yield budget; step 4 raises it automatically for pending function pairs |
| `--step-retries` | 5 | how many times a *stalled* server is restarted under the same step |

Without `--joern-cmd` the thresholds are switched off rather than honoured
pointlessly - a step that yielded would only yield again into the same server.

### Cost, and what it scales with

Step 4 dominates, and it scales with **function count, not repository size**.
Each function costs two Joern `importCode` + `run.ossdataflow` passes (OLD and
NEW). Measured at ~8 functions/minute:

| repo | CVEs | functions | step 4 |
|---|---|---|---|
| cJSON | 2 | 17 | seconds |
| gpac | 169 | 322 | ~40 min |

gpac's clone is under 400 MB; that number has almost no bearing on the runtime.
The paper reports the same (Sect. 5.3): 295 s per CVE on average, driven by the
number of commits touching the file, the number of modified functions, and the
number of semantic pairs.

Large repositories therefore need a raised `--step-timeout` (default 7200 s):

```bash
python scripts/clovery/clovery_cycle.py run --only "gpac@gpac" --limit 1 \
    --full-clone --step-timeout 43200
```

Step 5 (`-II_getHistory`) used to be the other half of that problem, and for a
different reason: it fanned out over *repositories*. A cycle analyses one
repository at a time, so `executor.map` received a single task - 47 of 48
workers idled while one process walked every CombiPatchFunc entry in series.
Each entry costs a `git log --follow` plus a `git log -1 -L:<func>:<file>` per
commit touching the file (~3 s each on a 197k-commit repository), which put
tensorflow's 866 entries at ~13.5 h against a 2 h budget.

It now fans out per entry, over `--history-workers` processes (default: one per
usable core), after resolving each distinct file's history once - tensorflow's
866 entries name only 332 files, and `cuda_dnn.cc` alone is asked for 28 times.
Two things had to become parallel-safe for that: `commit_fname`'s ctags scratch
files, which were a fixed `old.cc`/`new.cc` shared by every worker, and its
`.vul` merge, which is a read-remove-write now held under a per-lineage-directory
`flock` (19 of tensorflow's entries share both a directory and a source file).

Lower `--history-workers` if memory is the binding constraint rather than cores:
one `git log -L` peaks near 650 MB on a repository that size.

A failed repository keeps its intermediates so `--retry-failed` resumes rather
than rebuilding every CPG; the next repository purges them at the start of its
own cycle.

Resuming means the retry also skips the two stages that already finished and are
expensive enough to dominate it: patch-commit recovery, which greps the whole
history once per CVE, and the release boundaries, which walk `git tag --contains`
per commit. On tensorflow those two took **5 h 13 min** of a 5 h 55 min run - far
more than the Joern steps the retry is actually for. The boundaries are read back
from `fixed_versions.json`, which is why that file is written before step 2.

Resuming is refused unless the intermediates are demonstrably this repository's:
`Evalu/.cycle_pack` records whose they are, and the run's augmented feed has to
still be present. A cycle for any other repository in between replaces both, and
resuming on top of that would silently mix two repositories' work.

## Output

```
workspace/clovery/
  targets.json              the plan, sorted by DB-bound CVE count
  feeds/<owner##repo>.json  per-repo 1.1 feed
  results/<owner##repo>/
    patch_evidence.json      candidate source, commit, changed files and reject reason per CVE
    collector_status.jsonl   local Git diff collection outcome per selected commit
    tagCombi/*.json         per git tag: Vulnerable | Safe | Unknown  (Clovery)
    tagCombi_allSafe/*.json CVEs where no tag came back vulnerable
    fixed_versions.json     fixed version per release series (patch commit)
    version_ranges.json     published vs derived range + proposed update
    summary.json            verdict counts, `coverage` (how many CVEs survived
                            each stage, and which ones did not), and
                            `abandoned_functions` (given up on after repeated
                            query timeouts - named, not counted)
  state.json                done / failed / skipped, for resume
  logs/<owner##repo>.log    full step output
  logs/joern.log            the server the cycle starts and restarts
```

One more file lives with the intermediates rather than the results:
`Evalu/Joern_result/query_timeouts.json`, the per-function attempt count behind
`abandoned_functions`. It is purged with the rest of a repository's working
state, which is the lifetime wanted - an attempt count must survive the step
reruns within one repository and nothing beyond that.

The version signals are independent and cross-check each other. On cJSON:

```
CVE-2019-1010239   published: 1.7.8 - 1.7.8      (NVD lists one version)
                   derived  : 1.4.0 - 1.7.8, fixed in 1.7.9
                   confidence high - Clovery's next release after the last
                   vulnerable tag equals the commit-derived fixed version
CVE-2016-10749     no affected release: the commit predates every tag, and
                   Clovery independently tags all 49 releases Safe
CVE-2025-57052     published: 1.5.0 - 1.7.18
                   derived  : 1.5.0 - 1.7.18, fixed in 1.7.19
                   confidence high - both signals reproduce the published range
```

`coverage` exists because a CVE leaves the pipeline by simply not producing its
next artifact, and nothing used to say so. It now names each transition
separately: `no_patch_diff`, `no_function_extracted`, `no_tag_info`, and
`unanalysable`. A macro-only change can therefore be distinguished from a failed
download, a function extraction failure, and a tag-verdict failure.

Verification runs after harvest, so `version_ranges.json` reflects the tagCombi
output of the same cycle. To re-verify without re-running Clovery:

```bash
python scripts/clovery/verify_version_range.py \
    --all-results workspace/clovery/results --changed-only
```

`fixed_versions.json` is produced right after the clone, before the expensive
Joern steps, so the release boundary survives even when later stages fail.

## Scope

Of the 19,528 corpus repositories, **1,176 resolve to a DB product** under the
two strict tiers. Direct NVD references produce 443 targets. Adding matching OSV
GIT `fixed` events produces the 605-repository upper-bound plan:

```
19,528 corpus repos
 1,176 resolve to a DB product      (377 exact pair, 66 <name>_project, + cluster)
   443 have a direct NVD commit
   572 have a matching OSV fixed event
   605 in their union               -> 4,622 candidate repo-CVE pairs
                                      (4,615 distinct CVE)
                                       9,201 bound repo-CVE pairs in DB
                                      (9,121 distinct CVE)
```

This is an upper bound, not a promise that 4,622 repo-CVE pairs reach Joern. Local commit
validation and the stage coverage ledger provide the lower, evidence-backed
count. `status` reports old completed repositories as `legacy` until they have
been rerun with the new validator. `--repo-name-match` adds the product-name-only
tier, which recovers more repos at the cost of collisions on generic names.
