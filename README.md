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
    - Generates SHA-256 checksums and XML/PREMIS metadata
    - Recreates the full directory structure from the input directory
- Sample output:
  <img width="1851" height="961" alt="image" src="https://github.com/user-attachments/assets/ab99a52b-f137-463c-a2c8-50fc3f217ce1" />



## FITS
- Identifies file formats and extracts technical metadata
- Uses the bundled FITS 1.6.0 distribution with the project's DROID-focused configuration
- Records PRONOM/PUID format identification when available


## XSLT Processor
- Parses the XML report from the accession process
- Output: CSV and HTML reports
- How the function works:
    - Transforms the XML report into CSV and HTML reports
    - Includes file metadata and checksums
- Sample output
    - CSV:
      <img width="1772" height="324" alt="Screenshot 2025-12-08 131338" src="https://github.com/user-attachments/assets/b239666f-0293-4726-b61a-8691ff9fb6c1" />

    - HTML:
      <img width="971" height="691" alt="Screenshot 2025-12-08 131635" src="https://github.com/user-attachments/assets/5a1a1d4b-b57a-470d-8ebb-58ef80b411c2" />


## Fixity Verification
- Uses Python's `hashlib` to validate file checksums against the accession metadata
- Output: CSV and log report
- How the function works:
    - Recalculates SHA-256 checksums and compares them with the stored values
    - Reports matching, modified, missing, or unreadable files
- Historical MD5 accessions remain verifiable using their recorded checksums.
- Sample output
    - CSV:
      <img width="1725" height="296" alt="Screenshot 2025-12-08 132042" src="https://github.com/user-attachments/assets/5d8979f0-9566-40ac-a520-ea1b2388d696" />

    - Log:
      <img width="1856" height="466" alt="Screenshot 2025-12-08 132132" src="https://github.com/user-attachments/assets/c4ef74c0-e006-4ced-b952-62ab97164c75" />


## Virus scanning
- Uses Microsoft Defender for an optional antivirus scan before ingest.


## Bagging function (optional)
- Packages files and metadata using BagIt with SHA-256 manifests and tag manifests.
- Supports generic and APTrust bags.
- Bag validation and TAR serialization can also be run when needed.


## Resume / Status
- Processing steps can be selected and run separately.
- The pipeline keeps a status file so users can return later and continue unfinished processing.

Run regression tests with `python -m unittest discover -s tests -v`.
