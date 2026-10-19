# Environment setup

Use Python 3.10 or later with Tkinter available. Official Python installers for Windows include Tkinter; on Linux, install your distribution's Tkinter package if needed (for example, `python3-tk`).

Optionally create a virtual environment in the repository root:

```sh
python -m venv .venv
```

Activate it with `.venv\Scripts\Activate.ps1` in Windows PowerShell or `source .venv/bin/activate` on macOS/Linux, then follow [Installation](INSTALLATION.md).

## Python dependencies

`requirements.txt` installs `lxml` for XML/XSLT processing and `bagit` for optional BagIt construction and validation. Other application imports are part of Python's standard library; do not install them with pip.

## FITS and Java

Keep the complete bundled `fits/` directory. The application automatically discovers `fits/tools/fits-1.6.0/` relative to the application files and uses `fits/config/fits-droid.xml`.

Install Java and check `java -version`. Java must be available on `PATH`, or set `JAVA_HOME` to the Java installation directory containing `bin/java` (`bin/java.exe` on Windows). To use another FITS distribution, set `FITS_HOME` to its extracted root containing the launcher and `lib/` directory.

If FITS or Java is unavailable, format identification is skipped with a warning; file transfer and baseline metadata still work. See [FITS configuration](../fits/FITS-configuration.md) for configuration details.

## Optional antivirus scanning

The antivirus step uses Microsoft Defender on Windows when available.
