# Archives Pipeline

Archives Pipeline transfers accession files, identifies file formats, creates metadata reports, verifies fixity, and optionally packages collections for preservation. The GUI lets users select the processing steps they need and continue an accession later.

The project builds on Data Accessioner-style ingest, FITS/DROID format identification, XSLT reporting, Python's hashlib for fixity, Microsoft Defender scanning, and APTrust's Digital Archivist's Resource Tool (DART)-style BagIt packaging.

## Requirements / Installation

- Python with the required packages; BagIt support is needed for optional packaging.
- FITS and Java for format identification; FITS is included in the repository.
- Microsoft Defender on supported Windows systems for optional virus scanning.

See [installation instructions](installation) and [Python library requirements](setup.md) for setup details. [FITS/DROID notes](FITS-droid-only.md) describe the supplied identification configuration.

## Running the Pipeline

From the project folder, run:

```sh
py GUI.py
```

Choose an input folder, output folder, and accession name, select the desired steps and options, then click **Run Selected Steps**. To continue an existing accession, use its output folder and accession name, then **Load / Refresh Status**.

## Processing Steps

1. **Ingest:** Optionally scan with Microsoft Defender, then copy or move accession files while preserving their directory structure and timestamps.
2. **Format Identification:** Use FITS to identify file formats.
3. **Reports:** Create CSV/HTML metadata reports and a collection summary.
4. **Fixity:** Verify file checksums and report missing or changed files.
5. **Bagging:** Optionally create a BagIt package, validate it, and produce an APTrust TAR archive where selected.

## Resume / Status

Processing progress is stored in an accession status file so users can reopen an accession and continue later. Completed work can be reused when appropriate; changed outputs may be marked stale and rerun.

## Output

Outputs may include accession XML, CSV/HTML metadata reports, a collection summary, a fixity report, and BagIt/TAR output when selected.

## Tests / Development

The project includes automated tests for processing, status tracking, resume behavior, and packaging.
