# Building NetHawk Pro Executable

This guide explains how to package NetHawk Pro as a Windows executable (.exe) file.

## Prerequisites

1. **Python 3.7+** installed on Windows
2. **All dependencies** installed (see requirements.txt)

## Quick Build

### Option 1: Using the batch file (Windows)
```batch
build_exe.bat
```

### Option 2: Using the Python script
```bash
python build_exe.py
```

### Option 3: Manual build
```bash
# Install PyInstaller if not already installed
pip install pyinstaller

# Build the executable
pyinstaller nethawk2_2.spec
```

## Installation Steps

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Build the executable:**
   ```bash
   python build_exe.py
   ```

3. **Find your executable:**
   - Location: `dist\nethawk2_2.exe`
   - The executable is standalone and includes all dependencies

## Output

After building, you'll find:
- `dist\nethawk2_2.exe` - The standalone executable
- `build\` - Temporary build files (can be deleted)
- `nethawk2_2.spec` - PyInstaller specification file

## Distribution

The `nethawk2_2.exe` file is a standalone executable that includes:
- All Python dependencies
- PyQt5 libraries
- Scapy libraries
- All required DLLs

**You can distribute just the .exe file** - no Python installation required on target machines!

## File Locations in Executable

When running the .exe, NetHawk will use:
- **Configuration:** `C:\ProgramData\NetHawk\nethawk_config.json`
- **Database:** `C:\ProgramData\NetHawk\nethawk_packets.db`
- **Logs:** `C:\ProgramData\NetHawk\network_analyzer.log`
- **Audio Exports:** `C:\ProgramData\NetHawk\audio_exports\`

## Troubleshooting

### Build fails with "Module not found"
- Make sure all dependencies are installed: `pip install -r requirements.txt`
- Try adding the missing module to `hiddenimports` in `nethawk2_2.spec`

### Executable is too large
- This is normal - PyInstaller bundles all dependencies
- Typical size: 50-150 MB
- You can enable UPX compression (already enabled in spec file)

### Executable won't run
- Check Windows Defender/Antivirus - sometimes flags new executables
- Run from command line to see error messages
- Check that all required DLLs are included

### Missing DLL errors
- Install Visual C++ Redistributable on target machine
- PyQt5 requires certain DLLs that should be bundled automatically

## Advanced Options

### Add an icon
1. Create or obtain an `.ico` file
2. Update `nethawk2_2.spec`:
   ```python
   icon='path/to/icon.ico',
   ```

### Create version info
1. Create `version_info.txt` with Windows version information
2. The spec file already references it

### Reduce executable size
- Remove unused imports from the code
- Use `--exclude-module` in spec file
- Enable UPX compression (already enabled)

## Notes

- The executable is built for the current Python version and architecture
- For 64-bit Windows, use 64-bit Python
- The first run may be slightly slower as files are extracted
- All user data is stored in `C:\ProgramData\NetHawk\` (not in the exe directory)

