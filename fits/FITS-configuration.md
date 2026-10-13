# FITS Configuration

FITS provides file-format identification for the Archives Pipeline.

## Current Implementation

The bundled FITS location is `fits/tools/fits-1.6.0/` and the active custom configuration is `fits/config/fits-droid.xml`. The project uses a DROID-focused FITS configuration; DROID provides the PRONOM/PUID identification used by the pipeline.

Java is required. The bundle is discovered relative to `pipeline.py`; an explicit FITS directory or `FITS_HOME` can override it. The custom profile also applies to overrides, so check compatibility with other FITS releases.

Only DROID is enabled, with no extension exclusions. Python supplies checksums and file sizes; FITS checksum calculation is disabled. DROID identifies formats rather than providing rich characterization or validation, and unknown formats may have no PUID.

## Enabling Additional FITS Tools

1. Back up or copy the current `fits-droid.xml`.
2. Inspect the bundled configuration files, especially `xml/fits.xml` inside the FITS installation.
3. Enable the desired tools in a copied configuration using their existing `<tool>` entries from the bundled configuration.
4. Keep DROID enabled if PRONOM/PUID output is still required.
5. Update the pipeline configuration path only if the new configuration uses a different filename or location.
6. Test with a small sample accession.
7. Verify the expected FITS metadata and PUID output.
8. Run the automated test suite: `py -m unittest discover -s tests -v`.
9. Compare processing performance if additional tools significantly increase runtime.

## Restoring the Current Configuration

Restore the original DROID-focused configuration and point the pipeline back to `fits/config/fits-droid.xml` to return to the project's current setup. Running a bundled FITS launcher without this custom profile uses the vendor's full tool configuration instead.

## Related Notes

- [Installation and diagnostics](../installation)
- [Bundled vendor configuration](tools/fits-1.6.0/xml/fits.xml)
