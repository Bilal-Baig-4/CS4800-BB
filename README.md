# Automation for Data Accessioner, XSLTProcessor, hashlib, Windows Defender, and DART. 

## Data Accessioner
- Transfers files from disks onto a file server
- Output: XML file and the full directory from the input
- How the function works:
    - Recursively copies or moves files from the input directory
    - Preserves the original file timestamps
    - Generates an XML report
    - Recreates the full directory structure from the input directory
- Sample output:
  <img width="1575" height="637" alt="Screenshot 2025-12-08 131822" src="https://github.com/user-attachments/assets/29061578-5ba5-47dd-8a93-fface00b151b" />


## XSLT Processor
- Parses the report from Data Accessioner
- Output: CSV and HTML reports
- How the function works:
    - Transfroms the XML report from previous function into a CSV and HTML report
- Sample output
    - CSV:
      <img width="1772" height="324" alt="Screenshot 2025-12-08 131338" src="https://github.com/user-attachments/assets/b239666f-0293-4726-b61a-8691ff9fb6c1" />

    - HTML:
      <img width="971" height="691" alt="Screenshot 2025-12-08 131635" src="https://github.com/user-attachments/assets/5a1a1d4b-b57a-470d-8ebb-58ef80b411c2" />


## Hashlib function
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
- Bundles files and metadata based on APTrust's Digital Archivist's Resource Tool (DART).

## This project <u>mimics</u> these 5 programs for automation.


