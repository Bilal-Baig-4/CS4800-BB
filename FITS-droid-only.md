# DROID-only FITS profile and verification

## Configuration

The Pipeline still runs bundled FITS 1.6.0 through its Java entry point. The
existing GUI → Pipeline → FITS → PREMIS → XSLT → HTML/CSV flow is unchanged.
Java remains required. Discovery still prefers an explicit `fits_home`, then
`FITS_HOME`, then the bundle relative to `pipeline.py`, then a launcher on PATH.

FITS 1.6.0's installed `-h` output confirms `-f <arg>` accepts an alternate
configuration file. Its [official user manual](https://www.fitstool.org/user-manual)
documents this option and the `<tools>/<tool>` class list. A class executes
only when listed; removing its entry from this profile disables it without
removing its libraries. `include-exts` and `exclude-exts` restrict extensions,
and list order determines preference between tools.

`pipeline.py` now passes the absolute path of `config/fits-droid.xml` with `-f`.
The profile is derived from the bundled configuration with these differences:

- The tool list contains only
  `edu.harvard.hul.ois.fits.tools.droid.Droid`, with `classpath-dirs="lib/droid"`.
- The original DROID `exclude-exts="odm,m4a,mpg"` is omitted. DROID attempts
  every input; those extensions no longer depend on another identifier.
- `output/enable-checksum` is `false`; Python already supplies PREMIS MD5.
- Other active settings, including signature filenames, remain unchanged.

Enabled: DROID (reports version 6.5.2).

Disabled: MediaInfo, AudioInfo, ADLTool, VTTTool, Jpylyzer, Jhove, EmbARC,
FileUtility, Exiftool, NLNZ MetadataExtractor, FileInfo, XmlMetadata, FFIdent,
and TikaTool. FITS itself still consolidates and serializes DROID's result.

The vendor `tools/fits-1.6.0/xml/fits.xml` and all distribution binaries and
libraries are unchanged. Calling a vendor launcher without `-f` still runs
the original full tool list. To re-enable tools for the Pipeline, copy their
original `<tool>` entries into the Pipeline profile and retest representative
formats. The profile is also used for explicit/environment-selected installs;
other FITS releases need compatibility checks for its layout and signatures.
A missing profile raises a nonfatal per-file identification error, never an
implicit fallback to full FITS.

## Validation

The regression suite covers PUID/registry, format/version/MIME, DROID provenance,
Python MD5/size, XML/HTML/CSV, full-FITS-to-DROID re-enrichment, missing profiles,
nonfatal FITS failures, COPY/MOVE, and bundled autodetection without FITS_HOME.
Historical full-FITS fixtures remain to test backward compatibility.

Commands from the repository root:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
$env:PIPELINE_TEST_FITS_HOME = (Resolve-Path tools/fits-1.6.0).Path
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Ordinary suite: 52 tests, 51 passed, one opt-in live test skipped.
Final suite with bundled live FITS enabled: **52 passed, zero failures/skips**
(8.07 seconds). `git diff --check` passes. GUI controls were not exercised
interactively; its underlying Step 2 entry point and both transforms were run.
Initial sandbox executions encountered Windows temporary-directory permission
errors; approved executions outside the sandbox are used for valid results.

## Benchmark method

The same 42-file `2005` accession used in `FITS-performance.md` was processed
in COPY mode into fresh output directories, through
`generate_data_accessioner_xml`, followed by both existing XSLT transforms.
This measures GUI Step 2 plus report generation, not antivirus or packaging.
The source remains in Downloads (`2005-20260909T211909Z-1-001/2005`). Java is
23.0.2. The prior measurements were collected on September 22, 2026; these
are new measurements, not simultaneous controlled comparisons.

The existing local `verification-output/profile_fits.py` was extended with an
optional worker count and captured process output. Raw XML, HTML, CSV, logs,
per-file timings and `verification.json` remain under ignored
`verification-output/profile-droid-*` directories. Local commands:

```powershell
.venv\Scripts\python.exe verification-output/profile_fits.py droid-sequential 1
.venv\Scripts\python.exe verification-output/profile_fits.py droid-two-clean 2
.venv\Scripts\python.exe verification-output/verify_droid.py droid-sequential droid-two-clean
```

These profiling helpers are local verification artifacts, as with the earlier
benchmark. FITS process sums overlap with two workers; they are neither elapsed
wall time nor CPU time. FITS internal examination statistics exclude much of
initialization/shutdown. Per-file JVM/process overhead remains substantial.

## Benchmark results

| Run | Step 2 seconds | XSLT seconds | Combined seconds |
| --- | ---: | ---: | ---: |
| Historical full FITS, one worker | 268.873 | 0.137 | 269.010 |
| Historical full FITS, two workers | 134.740 | 0.060 | 134.799 |
| DROID-only, one worker | 208.235 | 0.047 | 208.283 |
| DROID-only, two workers (clean repeat) | 105.062 | 0.049 | 105.111 |

The clean two-worker run reduces combined elapsed time by **22.02%** compared
with the supplied 134.80-second baseline, and **49.53%** compared with the new
sequential DROID run. Keep the existing two-worker default.

| FITS timing metric | One worker | Two workers |
| --- | ---: | ---: |
| Sum of subprocess durations | 205.973 s | 206.237 s |
| Wall time with a FITS process active | 205.973 s | 103.592 s |
| Sum of FITS internal examination times | 3.791 s | 3.684 s |

Each run identified **42/42 files**, with PUIDs for **42/42**. No Pipeline
warnings/errors or captured FITS stdout/stderr diagnostics occurred in these
two runs. FITS_HOME was unset: bundled autodetection worked in actual execution.
Sequential and parallel CSV rows, HTML file sections and PREMIS values match
after normalization of generated UUIDs; raw paths/times/statistics vary.

An initial successful parallel trial took 119.429 seconds (11.40% below the
historical baseline). It is retained as `profile-droid-two-approved`; the
105.111-second repeat followed the sequential trial. This variation means
22.02% is an observed result, not a guaranteed speedup or cold-cache average.
The earlier sandbox-denied run is excluded from performance/correctness claims.

Recommendation: use DROID-only FITS with two workers as the default for the
current identification scope. Required metadata and failure/transfer behavior
passed validation. Retain one-worker support for constrained machines, and test
additional format families before expanding the project's characterization scope.

## Sample and metadata tradeoffs

`Homecoming Magnet 05.pdf` retains these values through PREMIS XML, HTML and CSV:

| Field | Value |
| --- | --- |
| Format | Portable Document Format |
| Version | 1.2 |
| PUID | fmt/16 |
| Registry | http://www.nationalarchives.gov.uk/pronom |
| MIME | application/pdf |
| Provenance | Identified by: Droid v6.5.2 |
| Python MD5 | ac3e1b1127f7f5a5085aad9024db114f |
| Size | 293806 bytes |

All 42 format names, versions, PUIDs and MIME values match the saved full-FITS
baseline. Copied bytes, Python MD5, PREMIS fixity/size and filesystem modification
times are verified. No XSLT or PREMIS mapping changes were needed.

The raw FITS extension loses characterization previously supplied by other
tools: author/title/subject/category/language; document creation/modification
dates and creating application/version; page, word, character, paragraph,
line and graphics counts; annotation/hyperlink/outline/picture flags; and
valid/well-formed results. Duplicate FITS filename/path/filesystem timestamp,
MD5 and size fields also disappear. Python inventory/fixity/size and filesystem
timestamp handling remain intact. The current CSV's blank `last modified`
column is an existing inventory/export limitation, not a DROID regression.

Other formats can lose metadata not represented in this document-heavy sample.
DROID-only identification does not replace validation or rich characterization.
Signatures remain the bundled V109 Alt and 2022-11-02 container signatures;
signature modernization is a separate change. Unknown/new formats may lack PUIDs.
Removing stock exclusions needs broader testing for ODM/M4A/MPG, absent from
this collection. Successful re-enrichment replaces old FITS provenance; failed
files deliberately retain prior metadata under the existing nonfatal contract.
