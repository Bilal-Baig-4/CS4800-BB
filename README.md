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
      <img width="1780" height="193" alt="image" src="https://github.com/user-attachments/assets/77c7f8d0-6a58-4055-b66a-3265235e2fa6" />

    - HTML:
      <img width="1067" height="753" alt="image" src="https://github.com/user-attachments/assets/5d7a0d46-17ff-4af4-b8e2-a08285e9ab39" />

## Fixity Verification
- Uses Python's `hashlib` to validate file checksums against the accession metadata
- Output: CSV and log report
- How the function works:
    - Recalculates SHA-256 checksums and compares them with the stored values
    - Reports matching, modified, missing, or unreadable files
- Historical MD5 accessions remain verifiable using their recorded checksums.
- Sample output
    - CSV:
      <img width="1835" height="187" alt="image" src="https://github.com/user-attachments/assets/ffa76b3e-831a-4ee8-b93e-696a1bee9067" />
      
    - Log:
      <img width="1702" height="447" alt="image" src="https://github.com/user-attachments/assets/84d3776e-263b-4120-8636-235ba5fe3c7a" />

## Virus scanning
- Uses Microsoft Defender for an optional antivirus scan before ingest.

## Bagging function (optional)
- Packages files and metadata using BagIt with SHA-256 manifests and tag manifests.
- Supports generic and APTrust bags.
- Bag validation and TAR serialization can also be run when needed.

## Resume / Status
- Processing steps can be selected and run separately.
- The pipeline keeps a status file so users can return later and continue unfinished processing.
