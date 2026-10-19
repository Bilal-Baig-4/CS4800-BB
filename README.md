# Archives Pipeline

Automation for Data Accessioner, FITS, XSLTProcessor, hashlib, Microsoft Defender, and DART.

## Installation

See [Installation](install/INSTALLATION.md) to install dependencies and run the application.

## Data Accessioner
- Transfers files from disks onto a file server
- Output: XML file and the full directory from the input
- How the function works:
    - Recursively copies or moves files from the input directory
    - Preserves the original file timestamps
    - Generates SHA-256 checksums during transfer using chunked reads
    - Stores each checksum in the XML `SHA256` attribute and PREMIS fixity metadata,
      with `messageDigestAlgorithm` set to `SHA-256`
    - Generates an XML report
    - Recreates the full directory structure from the input directory
- Ingest runs in Python and writes Data Accessioner-style XML; it does not invoke
  the external Data Accessioner application. `SHA256` extends the inventory;
  compatibility with external Data Accessioner schema validators has not been established.
- Sample output:
  <img width="1575" height="637" alt="Screenshot 2025-12-08 131822" src="https://github.com/user-attachments/assets/29061578-5ba5-47dd-8a93-fface00b151b" />


## FITS
- Identifies file formats and extracts technical metadata
- Uses the bundled FITS 1.6.0 distribution with the project's DROID-focused configuration
- Records PRONOM/PUID format identification when available


## XSLT Processor
- Parses the XML report from the accession process
- Output: CSV and HTML reports
- How the function works:
    - Transforms the XML report into CSV and HTML reports
    - Includes SHA-256 checksums; CSV also retains a labelled `md5` column for
      historical inventories, while HTML displays the recorded PREMIS algorithm and digest
- Sample output
    - CSV:
      <img width="1772" height="324" alt="Screenshot 2025-12-08 131338" src="https://github.com/user-attachments/assets/b239666f-0293-4726-b61a-8691ff9fb6c1" />

    - HTML:
      <img width="971" height="691" alt="Screenshot 2025-12-08 131635" src="https://github.com/user-attachments/assets/5a1a1d4b-b57a-470d-8ebb-58ef80b411c2" />


## Fixity Verification
- Uses Python's `hashlib` to validate file checksums against the accession metadata
- Output: CSV and log report
- How the function works:
    - Recomputes SHA-256 checksums (or MD5 for historical accessions) for all files in the accession
    - Compares the recomputed checksum to the recorded XML/PREMIS value
    - Records `algorithm`, `stored_checksum`, and `computed_checksum` in the CSV
    - Flags MISSING, MISMATCH, or ERROR (OK if they match)
- Sample output
    - CSV:
      <img width="1725" height="296" alt="Screenshot 2025-12-08 132042" src="https://github.com/user-attachments/assets/5d8979f0-9566-40ac-a520-ea1b2388d696" />

    - Log:
      <img width="1856" height="466" alt="Screenshot 2025-12-08 132132" src="https://github.com/user-attachments/assets/c4ef74c0-e006-4ced-b952-62ab97164c75" />


## Virus scanning
- Uses Microsoft Defender for an optional antivirus scan before ingest.


## Bagging function (optional)
- Bundles files and metadata into a BagIt package.
- Writes `manifest-sha256.txt` and `tagmanifest-sha256.txt` using SHA-256 digests,
  including APTrust tag files when selected.
- Verifies a supplied XML baseline using its recorded algorithm before moving payload files.
- Bag validation and TAR serialization can also be run when needed.
- Existing bags are not rebuilt automatically.


## Resume / Status
- Processing steps can be selected and run separately.
- The pipeline keeps a status file so users can return later and continue unfinished processing.

- Uses SHA-256 internal fingerprints for files, XML inventories, FITS metadata,
  reports, stylesheets, payloads, and bags. These are separate from preservation checksums.
- Payload fingerprints summarize relative paths, sizes, and exact modification
  timestamps; they do not replace content-based fixity verification. Bag fingerprints
  also include directory membership and tag/manifest content.
- On reopening, supported MD5-based status evidence is checked against its original
  fingerprint before conversion to SHA-256. Unchanged evidence is upgraded without
  reprocessing; changed evidence stays stale, and missing or unsupported evidence
  remains unverified. Status records are saved through the existing atomic writer.
- Recorded settings, FITS profile changes, and checksum workflow versions also affect
  freshness. Earlier checksum workflow completions cannot be reused as SHA-256 processing.
- Historical MD5 accession metadata remains unchanged and verifiable using MD5.
  New preservation checksums and internal fingerprints use SHA-256. MD5 hashing is
  retained only for historical preservation checks and validation of old status evidence.
- Historical verification outputs and screenshots remain examples of earlier runs;
  they are not relabelled as SHA-256 outputs.

Run regression tests with `python -m unittest discover -s tests -v`.
