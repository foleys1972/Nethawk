# How to Update NetHawk.exe

## Quick Update (Recommended)

Simply run the build script:

```batch
build_exe.bat
```

This will:
1. ✅ Check for Python and PyInstaller
2. ✅ Clean previous builds
3. ✅ Build a new `Nethawk.exe` with all latest changes
4. ✅ Place it in `dist\Nethawk.exe`

---

## Step-by-Step Process

### Option 1: Using the Batch File (Easiest)

1. **Open Command Prompt or PowerShell** in the project directory
2. **Run the build script:**
   ```batch
   build_exe.bat
   ```
3. **Wait for build to complete** (usually 3-5 minutes)
4. **Find your updated executable:**
   - Location: `dist\Nethawk.exe`
   - This is a fresh build with all your latest code changes

### Option 2: Manual Build

If you prefer to build manually:

```batch
# Clean previous builds
rmdir /s /q build
rmdir /s /q dist

# Build the executable
python -m PyInstaller --clean nethawk2_2.spec
```

---

## What Gets Updated

When you rebuild `Nethawk.exe`, it includes:
- ✅ All code changes from `nethawk2_2.py`
- ✅ All dependencies (PyQt5, Scapy, etc.)
- ✅ Latest fixes and features
- ✅ Custom icon (`nethawk.ico`)
- ✅ Version information (if `version_info.txt` exists)

---

## Before Building

Make sure you have:
1. **Python 3.7+** installed
2. **All dependencies** installed:
   ```batch
   pip install -r requirements.txt
   ```
3. **PyInstaller** installed (will be auto-installed by `build_exe.bat` if missing)

---

## After Building

1. **Test the new executable:**
   ```batch
   dist\Nethawk.exe
   ```

2. **Replace old executable** (if you have one deployed):
   - Stop the old NetHawk if it's running
   - Copy `dist\Nethawk.exe` to your deployment location
   - Start the new version

3. **Note:** All data (database, config, logs) is stored in `C:\ProgramData\NetHawk\`, so your data persists across updates.

---

## Troubleshooting

### Build Fails with "Module not found"
```batch
# Install missing dependencies
pip install -r requirements.txt
```

### Icon Doesn't Update
Windows caches icons. Try:
1. Refresh Explorer (F5)
2. Move the .exe to a different location
3. Clear icon cache: `ie4uinit.exe -show`
4. Restart Windows Explorer or reboot

### Executable is Large
This is normal! PyInstaller bundles all dependencies. The executable is typically 50-150 MB.

### Build Takes Too Long
- First build: 5-10 minutes (normal)
- Subsequent builds: 3-5 minutes
- If it's taking longer, check for antivirus interference

---

## Quick Reference

| Task | Command |
|------|---------|
| **Update NetHawk.exe** | `build_exe.bat` |
| **Update NetHawkService.exe** | `build_service.bat` |
| **Clean and rebuild** | Delete `build` and `dist` folders, then run `build_exe.bat` |
| **Check build output** | Look in `dist\` folder |

---

## Important Notes

- **Data Persistence:** Your database, config, and logs are in `C:\ProgramData\NetHawk\` and will NOT be affected by rebuilding
- **No Re-installation Needed:** The executable is standalone - just replace the old .exe with the new one
- **Backup First:** If you have a working version, consider backing it up before updating

---

## Build Output Location

After building, you'll find:
- **Main Application:** `dist\Nethawk.exe`
- **Service:** `dist\NetHawkService.exe` (if you built the service)
- **Build Files:** `build\` folder (can be deleted after successful build)

