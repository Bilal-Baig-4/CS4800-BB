# Automation for Data Accessioner, FITS/DROID, XSLTProcessor, hashlib, Windows Defender, and DART.

## Data Accessioner

The Pipeline implements Data Accessioner-style ingest and transfer in Python;
FITS/DROID format identification runs as a separate component.

- Transfers files from disks onto a file server.
- Output: XML file and the full directory from the input.
- How the function works:
  - Recursively copies or moves files from the input directory.
  - Preserves the original file timestamps.
  - Generates UUIDs for files.
  - Calculates baseline MD5 checksums and file sizes.
  - Generates the basic accession XML.
  - Recreates the full directory structure from the input directory.
- Sample output:
  <img width="1575" height="637" alt="Screenshot 2025-12-08 131822" src="https://github.com/user-attachments/assets/29061578-5ba5-47dd-8a93-fface00b151b" />


## FITS / DROID Format Identification

- Uses the bundled FITS 1.6.0 installation for file-format identification.
- FITS is currently configured to run only DROID.
- DROID uses PRONOM file signatures to identify file formats and PUIDs.
- Adds format metadata to the accession XML, including:
  - Format name
  - Format version, when available
  - MIME type, when available
  - PRONOM PUID
  - PRONOM registry information
  - DROID identification information
- Other FITS tools remain bundled but are disabled for now and can be enabled later if additional technical or preservation metadata is needed.
- FITS is included under `tools/fits-1.6.0` and is detected automatically by the Pipeline.
- Java is required to run FITS/DROID.

### Custom DROID-only FITS profile

FITS 1.6.0 remains bundled under `tools/fits-1.6.0`; Java is still required.
The Pipeline passes `-f config/fits-droid.xml` (as an absolute path) to FITS.
This Pipeline-specific profile enables only DROID for PRONOM/PUID format
identification. The vendor `xml/fits.xml` and all other tool binaries/libraries
remain intact. Direct vendor launcher calls without `-f` still use full FITS.

DROID supplies format name, version and MIME when available, PRONOM PUIDs,
and identifying-tool provenance. Python continues to supply MD5 fixity, size,
timestamps and transfers. The profile disables FITS checksum calculation.
Richer characterization/validation (such as page counts, embedded document
metadata and JHOVE validation) is no longer collected. Unrecognized formats
may have no PUID. Existing metadata is retained if FITS fails during enrichment.

To re-enable a tool later, copy its `<tool>` entry from the original FITS
configuration into `config/fits-droid.xml` and test representative files.
Only listed classes execute; there is no separate enabled/disabled switch.
DROID's stock `odm,m4a,mpg` exclusions are removed so it attempts every file.
Signature filenames and other FITS settings are unchanged. The profile also
applies to installations selected with `fits_home` or `FITS_HOME`; it targets
the bundled 1.6.0 layout/signatures, so validate it before using other releases.
Two concurrent per-file FITS processes remain the default.
See [DROID-only verification](FITS-droid-only.md) for measurements and limits.

## Independent ingest and FITS enrichment

The Python API supports ingesting an accession now and identifying its formats
later, before BagIt packaging:

```python
from pathlib import Path
from pipeline import ingest_accession, enrich_accession_with_fits

output = Path("output")
xml = ingest_accession("source", output, "A")
# Later, using only the existing payload and saved inventory:
enrich_accession_with_fits(output / "A", xml)
```

`ingest_accession()` copies/moves the selected files, preserves timestamps, and
writes the basic XML inventory with UUIDs, sizes and baseline MD5s. It never
configures or invokes FITS. Its optional arguments are `move_files`,
`clean_files_only`, and `progress_callback`.

`enrich_accession_with_fits()` reads the existing inventory and identifies only
its listed payload files. It preserves file records, UUIDs, sizes and baseline
checksums without retransferring or rehashing files. It accepts `fits_home`,
`fits_workers` (1 or 2, default 2), and `progress_callback`. Successful reruns
replace formats mapped from the previous embedded FITS report and replace that
FITS report, preserving unrelated metadata. Individual failures retain previous
metadata and allow other files to continue. Enriched XML replaces the original
only after successful serialization; unavailable FITS leaves the XML untouched.

`generate_data_accessioner_xml()` retains its existing signature and return
value as a wrapper running both stages consecutively. The GUI remains unchanged.
Its existing callback now reports the identification pass after ingest has
finished; each standalone stage can also report its own per-file progress.

This is not resume/status tracking. Calling ingest again still performs a fresh
ingest. Enrichment expects the unbagged payload layout and baseline PREMIS
characteristics produced by the current generator. Regenerate CSV/HTML reports
separately after later enrichment; FITS does not validate the saved MD5 baseline.

## XSLT Processor

- Parses the accession XML.
- Output: CSV and HTML reports.
- How the function works:
  - Transforms the XML report into CSV and HTML reports.
  - Includes available PREMIS format metadata such as format, MIME type, and PRONOM PUID.
- Sample output
    - CSV:
      <img width="1772" height="324" alt="Screenshot 2025-12-08 131338" src="https://github.com/user-attachments/assets/b239666f-0293-4726-b61a-8691ff9fb6c1" />

    - HTML:
      <img width="971" height="691" alt="Screenshot 2025-12-08 131635" src="https://github.com/user-attachments/assets/5a1a1d4b-b57a-470d-8ebb-58ef80b411c2" />

## Hashlib function
Python uses `hashlib` for baseline MD5 fixity and subsequent checksum verification.
- Parses the report from Data Accessioner, creates a list of files and their checksums, then validates those checksums with the checksums on the disk
- Output: CSV and log report
- How the function works:
    - Recomputes MD5 checksums for all of the files in the input directory
    - Compares original checksum to stored checksum
    - Flags MISSING, MISMATCH, or ERROR (OK if they match)
- Sample output
    - CSV:
      <img width="1725" height="296" alt="Screenshot 2025-12-08 132042" src="https://github.com/user-attachments/assets/5d8979f0-9566-40ac-a520-ea1b2388d696" />

    - Log:
      <img width="1856" height="466" alt="Screenshot 2025-12-08 132132" src="https://github.com/user-attachments/assets/c4ef74c0-e006-4ced-b952-62ab97164c75" />

## Virus scanning
- Runs local Microsoft Defender Antivirus scans using `MpCmdRun.exe`.
- Scans files individually and records clean, flagged, skipped, or error results.
- Uses `-DisableRemediation` so detections are reported without intentional remediation.
- Defender-flagged files can be excluded from ingest.
- Google-native files must be exported before their contents can be scanned.

## Bagging function (optional)

Optional DART-style BagIt packaging bundles files and metadata based on APTrust's
Digital Archivist's Resource Tool (DART). Packaging has three independent Python
operations (no DART invocation):

```python
from pipeline import construct_bag, validate_bag, serialize_bag_to_tar

bag = construct_bag(output / "A", "A", xml_manifest=xml,
                    profile="aptrust", title="Collection",
                    source_organization="Archives")
valid, error = validate_bag(bag)
if valid:
    tar_path = serialize_bag_to_tar(bag)
```

- `construct_bag()` returns the resolved bag directory on success and raises on
  failure. It validates settings and payload before moving anything. It rejects
  existing or ambiguous bags: top-level `data` (file or directory), `bagit.txt`,
  `bag-info.txt`, `aptrust-info.txt`, `fetch.txt`, and `manifest-*.txt` or
  `tagmanifest-*.txt` entries, case-insensitively. Original payload with those
  names is rejected too; nothing is automatically unbagged, remapped or rebuilt.
- Preflight rejects payload symbolic links/junctions, unsupported entry types,
  case-insensitive path collisions, and paths the current manifest writer cannot
  safely represent (line breaks, backslashes, percent signs, or leading/trailing
  whitespace in path components). Metadata must be single-line UTF-8 text.
- With `xml_manifest`, file membership must match exactly and every current MD5
  must match the saved baseline before payload movement. Missing, extra,
  changed, duplicate, or invalid inventory entries fail clearly. Unreadable XML
  never triggers fallback hashing. Without an XML baseline, construction hashes
  the current payload explicitly; this does not establish continuity with ingest.
- Construction moves payload into `data/` and creates MD5 payload/tag manifests
  and generic or APTrust metadata. It does not validate or serialize the bag.
  Accession XML is not modified; its paths remain logical payload-relative paths.
- `validate_bag()` returns `(valid, error)` using the installed `bagit` library.
  It can be repeated without rebuilding. This is BagIt validation, not a network
  check of the APTrust profile or a comparison against accession XML.
- `serialize_bag_to_tar()` accepts an existing generic or APTrust bag, checks
  basic structure, and returns its sibling `<bag-directory-name>.tar`. It does
  not validate checksums, regenerate manifests or move payload. The archive
  retains the bag's top-level directory. A temporary sibling is fully written
  and closed before `os.replace()` publishes it; a serialization/replacement
  failure leaves the prior completed TAR intact and attempts temporary cleanup.

The existing `create_bag()` signature and four-value return tuple remain the GUI
compatibility API. It constructs, optionally calls `validate_bag()`, and optionally
serializes APTrust bags. Requested validation failure prevents serialization;
when validation is not requested, existing TAR behavior remains allowed and
`bag_valid` is `None`. Construction errors propagate rather than reporting success.

Keep payload unchanged throughout preflight, construction, validation and
serialization: these operations do not lock out external writers. Construction
is in-place and has no rollback. Unexpected I/O failures can leave a partial bag;
diagnostics explain that it must not be automatically retried. Root `data/` or
tag-file indicators cause subsequent construction to reject that state.

Packaging remains a physical-layout boundary. Post-bag fixity/FITS discovery,
shared payload-root resolution, recovery, status/resume tracking, and selectable
GUI steps are not implemented. XML/reports remain beside the bag and are not
included in its TAR. The existing GUI detaches its file logging handlers during
packaging, so packaging diagnostics may be absent from the named pipeline log.

## Pipeline Overview
This project combines Data Accessioner-style ingest/transfer, separate FITS/DROID
format identification, XSLT-generated HTML/CSV reports, Python/hashlib fixity,
Microsoft Defender virus scanning, and optional DART-style BagIt packaging
into a single Pipeline workflow.

