# NetHawk Build Guide

## Quick Start

### Build Both Executables (Recommended)

```batch
build_all.bat
```

This creates:
- `dist\Nethawk.exe` - Main application with full GUI
- `dist\NetHawkService.exe` - Remote capture service (optimized, no GUI)

---

## Individual Builds

### Build Main Application Only

```batch
build_exe.bat
```

Creates: `dist\Nethawk.exe`

### Build Service Only

```batch
build_service.bat
```

Creates: `dist\NetHawkService.exe`

---

## Why is the Service File Size Important?

The **NetHawkService.exe** should be much smaller than **Nethawk.exe** because:

### Nethawk.exe (Main Application)
- ✅ Includes PyQt5 (full GUI framework) - ~30-50 MB
- ✅ Includes matplotlib, numpy (for charts/graphs) - ~20-30 MB
- ✅ Includes all UI components
- ✅ Full feature set
- **Expected size: 80-150 MB**

### NetHawkService.exe (Remote Service)
- ❌ **NO PyQt5** (excluded)
- ❌ **NO matplotlib, numpy, pandas** (excluded)
- ❌ **NO GUI components** (excluded)
- ✅ Only packet capture libraries (pcap/scapy)
- ✅ Only Windows service components (pywin32)
- ✅ Only network/socket libraries
- **Expected size: 15-40 MB** (much smaller!)

---

## Optimization Details

The service build uses `NetHawkService.spec` which explicitly:

### Excludes (Not Needed for Service):
- PyQt5 (GUI framework)
- matplotlib (charting)
- numpy (scientific computing)
- pandas (data analysis)
- PIL/Pillow (image processing)
- tkinter (GUI toolkit)
- IPython, jupyter (development tools)
- torch, tensorflow (ML frameworks)

### Includes (Needed for Service):
- socket, struct (network)
- logging (diagnostics)
- pcap/scapy (packet capture)
- win32service, win32serviceutil (Windows service)
- pywintypes (Windows integration)
- json, select (utilities)

---

## File Size Comparison

| Component | Nethawk.exe | NetHawkService.exe |
|-----------|-------------|-------------------|
| PyQt5 GUI | ✅ ~40 MB | ❌ Excluded |
| matplotlib | ✅ ~20 MB | ❌ Excluded |
| numpy | ✅ ~15 MB | ❌ Excluded |
| scapy | ✅ ~5 MB | ✅ ~5 MB |
| pywin32 | ❌ Not needed | ✅ ~3 MB |
| Python runtime | ✅ ~10 MB | ✅ ~10 MB |
| **Total** | **~80-150 MB** | **~15-40 MB** |

---

## Troubleshooting

### Service is Still Large

If `NetHawkService.exe` is still large (>50 MB), check:

1. **Is it using the optimized spec file?**
   - Should use `NetHawkService.spec`
   - Check build output for "Using optimized spec file"

2. **Are exclusions working?**
   - Check build log for excluded modules
   - Verify PyQt5 is not being bundled

3. **Rebuild with clean cache:**
   ```batch
   python -m PyInstaller --clean-cache
   build_all.bat
   ```

### Build Fails

1. **Missing dependencies:**
   ```batch
   pip install -r requirements.txt
   ```

2. **Spec file issues:**
   - Delete `NetHawkService.spec` and let it regenerate
   - Or manually edit to fix issues

3. **Permission issues:**
   - Run as Administrator if needed
   - Close any running instances of the executables

---

## Build Output Locations

After building:
- **Main App:** `dist\Nethawk.exe`
- **Service:** `dist\NetHawkService.exe`
- **Build files:** `build\` (can be deleted)
- **Spec files:** `*.spec` (keep these for future builds)

---

## Next Steps

1. **Test the main application:**
   ```batch
   dist\Nethawk.exe
   ```

2. **Install the service:**
   ```batch
   install_service.bat
   ```
   (Run as Administrator)

3. **Deploy to remote servers:**
   - Copy `NetHawkService.exe` to remote machines
   - Install and start the service
   - Connect from `Nethawk.exe` using Remote Capture tab

