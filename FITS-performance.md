# FITS performance investigation

Measured on Windows, 2026-09-22, using bundled FITS 1.6.0 and Java 23.0.2,
16 logical processors and 16 GiB RAM. The 2005 collection contains 42 files.
All runs used fresh output folders and COPY mode through
`generate_data_accessioner_xml`, followed by both existing XSLT transforms.

## Diagnosis and baseline

Originally, `generate_data_accessioner_xml` copied/moved a file, restored its
timestamps, calculated MD5, and synchronously called `identify_with_fits`.
That function launches the FITS Java main class in a new process with a unique
temporary XML report. It parses that report, then the caller maps it into PREMIS.
For N identified files, Python launches N FITS JVMs plus one Java version
preflight process. FITS tools can launch additional child processes.
`subprocess.run` applies a 300-second timeout per file; the caller logs failures
and continues without format metadata for that file.

The bottleneck is repeated FITS execution, not transfers, hashing or XSLT.
Baseline measurements were reported before changing production behavior.

| Operation | Total seconds | Average/file | % of measured total |
| --- | ---: | ---: | ---: |
| Copy | 0.121 | 0.0029 | 0.045 |
| MD5 | 1.042 | 0.0248 | 0.387 |
| FITS processes | 266.228 | 6.3388 | 98.966 |
| FITS XML parsing | 0.976 | 0.0232 | 0.363 |
| PREMIS mapping | 0.010 | 0.0002 | 0.004 |
| HTML + CSV XSLT | 0.137 | 0.0033 | 0.051 |
| Step 2 + XSLT overall | 269.010 | 6.4050 | 100 |

Remainder includes Java preflight, filesystem operations, XML serialization and
Python overhead. This is **not the entire six-step GUI runtime**: antivirus,
BagIt, summaries and later fixity checks were outside the benchmark.

Slowest baseline files:

| File | FITS seconds |
| --- | ---: |
| 2005 HC Parade funding forml.xls | 15.801 |
| Funding05.xls | 6.529 |
| Co-Chair responsibilities2005.doc | 6.438 |
| Hilltop Media Pre Production Process.docx | 6.415 |
| Winners05.doc | 6.409 |

FITS's reported internal examination times sum to 20.573 seconds. The remaining
245.655 seconds of process time includes initialization, compilation, report
serialization and shutdown; it cannot honestly be labeled pure JVM startup.
Separate `java -version` and FITS help probes took 0.154 and 0.290 seconds, but
neither initializes the full identification toolchain. The first baseline file
was an outlier; these are single-run observations, not controlled cold/warm
cache averages.

## Alternatives evaluated

Installed CLI help, launcher scripts and JAR bytecode were inspected. FITS can
process a directory recursively using `-r -n -i DIRECTORY -o OUTPUT_DIRECTORY`.
It emits separate `filename.ext.fits.xml` reports, not one combined report.
There is one input argument, with no arbitrary file-list interface in this CLI.
A six-file experiment included PDF, DOC, XLS, DOCX and duplicate basenames in
different subdirectories. All six reports mapped correctly using their relative
output locations and embedded `fileinfo/filepath`. A production implementation
would still need to validate reports against the selected transfer manifest.

| Strategy | Measured/expected speed | Complexity and correctness | Logging, timeout, reproducibility |
| --- | --- | --- | --- |
| A: sequential per-file | Six files: 37.89 s | Existing behavior; minimal complexity | Ordered logs; isolated 300 s timeout per file; fresh process per file |
| B: directory batch | Six files: 7.63 s | Largest gain, but needs manifest/report matching, filtering and partial-failure recovery; CLI skips `.DS_Store` | One process failure/timeout can affect remaining files; reused tool state requires more validation |
| C: two per-file workers | Six files: 18.34 s; full collection about 2x faster | Small bounded change; separate processes and report directories; ordered XML assembly | Same per-file timeout and errors; Pipeline logs assembled in input order; vendor logs can interleave |
| D: cache/reuse | No content-cache hits in this collection: all 42 SHA256 hashes differ | Correct cache keys need tool versions, signatures and configuration; raw metadata includes path/time | Cache hits change tool execution/logging; invalidation and provenance require additional design |

The installed Nailgun server script suggests persistent-JVM reuse, but requires
an additional server/client setup. It was not adopted. A separate experiment
with `-XX:TieredStopAtLevel=1` took 54.96 seconds for six files and was rejected.
Batch and parallel experiments preserved identities after accounting for the
ExifTool diagnostic variation described below.

## Implemented change

Choose **two concurrent per-file identifications**. Keep the existing transfer
and XML architecture, signature/tool configuration, and PREMIS mapping intact.
`fits_workers=1` selects sequential processing; the default is 2. Other values
are rejected to prevent accidental unbounded resource use.

Only `identify_with_fits` runs in workers. Transfers and hashing remain on the
calling thread. At most two results are pending, and the main thread consumes
them in traversal order, handles the existing nonfatal failures, restores file
timestamps and builds the XML. The timeout starts inside each subprocess call,
not while waiting for its result. No XSLT changes were needed.

The optional progress callback receives the current file number, total and
relative path before waiting for that file's result. GUI Step 2 posts this text
through `root.after`; it is current-file progress, not a percentage of FITS work.
Callback failure is logged without aborting the accession.

Core diff:

```python
# generate_data_accessioner_xml(..., fits_workers=2, progress_callback=None)
with ThreadPoolExecutor(max_workers=fits_workers) as executor:
    # Existing sequential transfer and MD5 calculation ...
    future = executor.submit(identify_with_fits, dest_path, *fits_config)
    # Bounded queue; consume in input order.
    # Existing error handling and PREMIS mapping use future.result().
```

## Results and validation

| Metric | Sequential | Two workers |
| --- | ---: | ---: |
| Step 2 wall time | 268.873 s | 134.740 s |
| XSLT wall time | 0.137 s | 0.060 s |
| Combined wall time | 269.010 s | 134.799 s |
| Sum of FITS subprocess durations | 266.228 s | 266.059 s |
| Wall time with at least one FITS process running | 266.228 s | 134.383 s |
| Average FITS subprocess duration | 6.339 s | 6.335 s |

Combined elapsed time improved **49.89%**. Summed process durations overlap in
the parallel run and must not be interpreted as elapsed time or CPU time.

All 42 files logged `IDENTIFIED`, with no Pipeline warning/error. File order,
attributes, MD5/fixity, size, format name/version, MIME, PUID and identifying
tools matched between runs. CSV rows and HTML file sections matched after the
normalizations below. Copied bytes matched source bytes; UUIDs parsed correctly;
destination modification times matched source times within one microsecond.
Existing and new tests additionally cover timestamps, hierarchy, filtering,
MOVE mode, missing FITS and nonfatal tool failures.

`Homecoming Magnet 05.pdf` retained Portable Document Format 1.2,
`application/pdf`, and `fmt/16` in PREMIS, HTML and CSV.

Reports are not byte-identical. UUIDs, ingestion times and embedded FITS
paths/timestamps/statistics naturally differ. This machine also emits an
ExifTool Perl locale warning inside its tool-version string: the same warning
lines and version `12.50` occur in different orders even in sequential trials.
The comparison normalized only that diagnostic line ordering and generated
UUIDs for exposed report values; production code does not alter those results.

Commands used (PowerShell, repository root):

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
$env:PIPELINE_TEST_FITS_HOME = (Resolve-Path tools/fits-1.6.0).Path
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Normal suite: 20 tests, 19 passed, one opt-in live test skipped. With the above
environment variable: **20 passed, zero failures/errors/skips**.
New deterministic tests force out-of-order completion, verify the concurrency
limit, compare sequential/parallel PREMIS/HTML/CSV, exercise progress/filtering,
and ensure one timeout does not lose another file's metadata or break MOVE.

Local profiling commands (scripts and results intentionally remain ignored in
`verification-output/`; these are not files shipped by the repository):

```powershell
# baseline2 was measured before changing production behavior.
.venv\Scripts\python.exe verification-output/profile_fits.py baseline2
.venv\Scripts\python.exe verification-output/profile_fits.py parallel2
.venv\Scripts\python.exe verification-output/compare_profiles.py baseline2 parallel2
```

The wrapper times the existing Pipeline entry point, not a replacement transfer
implementation. It patches copy, hashing, subprocess, parsing and mapping calls
to collect durations. Result directories must be fresh; use new labels to repeat.

## Limits and follow-up

Two JVMs consume more resources. A point sample observed roughly 364 MiB for
one JVM, not a guaranteed peak; native children add memory. FITS itself permits
up to 20 tool threads per instance. Four workers were not adopted or benchmarked;
two were selected conservatively. CPU utilization was not sampled continuously.
On constrained laptops use `fits_workers=1` at the Python entry point; no new GUI
configuration control was added.

Pipeline report paths are unique and XML writes are serialized. FITS's bundled
vendor logger still targets a shared `fits.log`, so its diagnostic lines may
interleave. Native tool temporary-file behavior for every format has not been
exhaustively audited. The tested formats completed without collisions. The
pre-existing timeout implementation does not introduce new process-tree cleanup
guarantees. GUI progress wiring was tested via callbacks and syntax checks, not
an automated interactive GUI session.

Track this as a **separate performance issue** from the resolved missing-PUID
bug. Potential follow-ups are larger/low-memory benchmarks, batch failure
isolation, and the existing ExifTool locale/version diagnostic problem. No FITS
bundle, XSLT or identification mapping changes are part of this optimization.
