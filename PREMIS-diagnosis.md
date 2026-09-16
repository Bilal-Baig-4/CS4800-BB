# Missing PREMIS metadata: diagnosis and verification

The Pipeline never invoked DataAccessioner. `README.md` explicitly says this
project mimics the programs. `GUI.py::run_pipeline` calls the Python function
`pipeline.py::generate_data_accessioner_xml`, which copies/moves files, hashes
them, and constructs its own XML. Before this fix, that function emitted only
`premis:objectIdentifier` inside each PREMIS object. It stored MD5 and size as
attributes of `da:file`, not as PREMIS characteristics.

At initial diagnosis there were no sample accession XML files or bundled
FITS/DROID installations in the repository. The diagnosis is based on the generator and its call
sites, not an assumed examination of an external user's report.

## Original data flow and evidence

1. `GUI.py::run_pipeline` optionally scans and filters files, then calls
   `generate_data_accessioner_xml` with copy/move and clean-file settings.
2. That function creates `<output>/<accession>/` containing transferred files
   and writes `<output>/<accession>.xml`. Files appear directly under the
   accession with relative paths in `name`; it does not create XML folder nodes.
3. Before the fix, each file had `name`, `size`, and `MD5` attributes and a
   PREMIS object containing UUID type/value only. There was no
   `objectCharacteristics`, `fixity`, `format`, `formatDesignation`,
   `formatName`, `formatVersion`, `formatRegistry`, `formatRegistryName`,
   `formatRegistryKey`, PUID, or identified MIME type. No tool was invoked to
   generate them.
4. `run_xslt_processor` parses that exact XML with lxml, applies the selected
   stylesheet, and writes the result. There is no intermediate XML rewrite.
   GUI output names are `<accession>_files.csv` and `<accession>_files.html`.
5. `files.html.xslt` already tests for
   `premis:objectCharacteristics/premis:fixity` and `.../premis:format` before
   displaying Fixity and Formats. Both conditions were false. It already
   renders format name/version, registry key/name, identification notes and
   MIME (the first formatNote, following DataAccessioner's convention).
6. `files.csv.xslt` already contains format, version, PUID, tool, and MIME
   columns with the appropriate PREMIS v2 paths. Missing nodes yielded blanks.
   Its original `xsl:value-of` expressions also selected only the first result.
7. `generate_summary_report` separately guesses MIME types with Python
   `mimetypes`; it never feeds those guesses back into XML. `run_fixity` and
   `create_bag` consume file MD5 attributes; neither removes PREMIS metadata.

This is primarily a missing XML-generation/identification implementation,
not a bad DataAccessioner command-line flag, parser loss, or stylesheet failure.

## Comparison with DataAccessioner

The inspected upstream DataAccessioner implementation wraps FITS:

- [DataAccessioner README](https://github.com/DataAccessioner/DataAccessioner)
- [MetadataManager.java](https://github.com/DataAccessioner/DataAccessioner/blob/main/src/main/java/org/dataaccessioner/MetadataManager.java):
  `addDocumentXSLT` transforms a FITS document and attaches the PREMIS object.
- [metadataManager.xsl](https://github.com/DataAccessioner/DataAccessioner/blob/main/src/main/resources/xml/metadataManager.xsl):
  maps FITS fileinfo MD5/size, each identity's format/version, DROID external
  identifiers, MIME and tools into PREMIS v2. It also maps some DROID notes.
- [FITS Windows launcher](https://github.com/fitstool/fits/blob/master/fits.bat):
  runs `edu.harvard.hul.ois.fits.Fits` using the distribution's library JARs.

The normal rich report is possible because these structures exist before the
report transformation. This Pipeline did not implement that FITS stage at all.
The upstream mapping uses XSLT 2.0 and Java UUID extensions, so it cannot simply
be run with the Pipeline's lxml XSLT 1.0 processor.

## Scoped fix

- `pipeline.py`: `identify_with_fits` runs FITS via its Java entry point with
  an argument list, an explicit working directory and a five-minute timeout.
  `generate_data_accessioner_xml` accepts optional `fits_home`, defaulting to
  `FITS_HOME`, and identifies only transferred files. Missing tools or failed
  identification produce a warning and leave transfer behavior intact.
  `add_object_characteristics` always records the existing checksum and size
  in PREMIS, and maps real FITS identities when available. PUIDs are accepted
  only from PUID/DROID external identifiers with `fmt/number` or `x-fmt/number`
  syntax. No extension mapping or guessed MIME is used.
- Complete FITS XML is retained in `objectCharacteristicsExtension`, preserving
  technical details, conflicts, and warnings beyond the mapped report fields.
  The Pipeline checksum remains the authoritative transferred-file checksum.
- `files.html.xslt`: separate format name and version with a space and display
  all registries. The existing MIME rendering is unchanged.
- `files.csv.xslt`: preserve all format/version/PUID/tool/MIME values with ` | `
  separators and escape quotes in those fields. Existing columns stay in order.
- `GUI.py`: unchanged; the existing Python workflow and call signature remain.
- `installation`: document optional FITS/Java setup, also usable by the GUI
  without new UI controls.
- `tests/test_premis.py`: self-contained synthetic FITS fixtures and an opt-in
  live FITS test; no additional Python testing dependency.

Representative generator change:

```diff
 checksum = compute_md5(dest_path)
+fits_result = identify_with_fits(dest_path, fits_home)  # when configured; failures logged
 ... create existing UUID ...
+add_object_characteristics(premis_obj, checksum, dest_path.stat().st_size, fits_result)
```

## Tests and results

```powershell
.venv/Scripts/python.exe -m unittest discover -s tests -v
git diff --check
```

All 15 automated tests passed with FITS 1.6.0 and Java 23.0.2, including the
opt-in live test (zero skips). Without live FITS configured, 14 tests pass and
the live test skips. The initial sandboxed test attempt could not access Windows
temp directories; the same command passed outside the sandbox.

Tests cover a synthetic FITS PDF result (`fmt/18`) through XML, HTML, and CSV;
format version 1.4 and application/pdf; multiple tools and identities; quoted
CSV format names; absent PRONOM identifiers; unavailable/timed-out FITS; invalid
tool XML; retained raw FITS XML; UUID validity; identical MD5/size; copied bytes;
nested relative paths; modification times; move/filter behavior; and existing
fixity verification returning OK. The architecture review also added coverage
for directory modification timestamps, repeated registries, missing executables,
nonzero tool exits, malformed XML, and nonfatal timestamp-restoration failure.

To verify actual content identification after installing FITS/Java:

```powershell
$env:PIPELINE_TEST_FITS_HOME = 'C:\Tools\fits'
.venv/Scripts/python.exe -m unittest discover -s tests -v
```

The live test creates a valid PDF 1.4 named `document.bin` and requires `fmt/18`
in XML, HTML and CSV, application/pdf, version 1.4, and unchanged basic metadata.
This checks content identification rather than an extension lookup.

## Limits

Live Java/FITS identification was verified with FITS 1.6.0 and Java 23.0.2.
The later 42-file copy-mode accession identified all files and passed all fixity
checks. Its PDF's fmt/16 appeared in XML, HTML and CSV. An earlier run had one
nonfatal FITS timeout; successful identification is not guaranteed for every run.
PUID availability depends on FITS's configured DROID/signatures and the input;
install/configure FITS to enable formats in normal GUI runs. Existing reports
are not retroactively enriched. FITS starts once per file and may be slow.
Reports expose selected PREMIS fields; full FITS detail remains in XML. CSV
joins multiple values and is not a lossless representation of their relationships.
The existing relative-path XML layout, UUID behavior, checksum attributes,
summary MIME guesses, and bagging architecture are preserved.

## Architecture review and final minimal scope

The workflow remains `GUI.py -> pipeline.py -> generated XML -> XSLT -> HTML/CSV`.
FITS is an optional metadata subprocess after Python transfers/hashes each file;
DataAccessioner itself is never launched. Existing copy/move, filtering, relative
paths, UUID generation, file attributes and directory restoration remain intact.

Essential generation changes are the optional FITS runner, real FITS-to-PREMIS
mapping, PREMIS checksum/size, and nonfatal identification errors. Restoring
timestamps after FITS is best-effort with a warning if it fails; such a failure
does not abort an accession. Ordinary pre-existing transfer/I/O errors can still
abort it. Complete FITS XML retention supports preservation of unmapped metadata.

Neither stylesheet needs a new PUID column or a new Fixity/Formats template.
The retained rendering fixes are necessary for the supported repeated structures:
CSV joins all values instead of silently taking only the first, escapes quotes
in metadata, and HTML loops over multiple registries. HTML's one-character space
prevents format and version from running together. Reverting these would still
render a simple single PUID, but would lose repeated values or readable formatting.

The optional GUI log wording changes and HTML MIME cleanup were reverted. Tests
and installation instructions remain supporting changes; this diagnosis document
is optional documentation. No transfer redesign or unrelated refactoring is part
of the final diff.

## FITS setup follow-up

The real accession's fixity/size without formats is consistent with unset
FITS_HOME. The bounded machine check found working Java 23.0.2 on PATH, with
JAVA_HOME unset, and no FITS launcher in the repository or checked common tool,
Downloads, Documents, and Desktop locations. This is not a full-disk inventory.

`configure_fits` now validates the explicit fits_home argument or FITS_HOME once
per accession, falling back only to a launcher on PATH when neither is set.
It checks the platform launcher, library JARs, and Java execution. The launcher
is a distribution marker; the existing direct Java FITS invocation is retained.
Global setup failures log once and skip identification for the accession.
Per-file logs distinguish timeout, exit status/diagnostics, invalid XML, I/O
failure, no identification, and successful identification (including PUIDs).
Unknown generic identities are not promoted to identified PREMIS formats;
the complete raw FITS XML is still retained.

No GUI, transfer, or stylesheet changes were needed for this follow-up.
See `installation` for complete Windows Java/FITS setup, temporary and permanent
configuration, direct FITS execution, real GUI accession checks, and log codes.
The normal tests mock Java/FITS and now also verify configuration failures,
PATH fallback, one warning for multiple files, and the configured execution path
through HTML/CSV.

The subsequent GUI discrepancy was configuration, not a different code path:
the failed accession logged FITS:NOT_CONFIGURED because neither FITS_HOME nor a
launcher on PATH was available. The live test supplies fits_home explicitly.
Repeating the GUI's generator call with FITS_HOME set in the launching shell
identified all 42 files, including the previously timed-out file. Persisting
FITS_HOME requires restarting parent applications such as VS Code; a variable
set in a separate shell is not inherited by an already-running GUI.
