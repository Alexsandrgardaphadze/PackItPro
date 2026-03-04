### PackItPro — Changelog

## v0.6.5 (Current)
- **CRITICAL FIX:** Errors now visible via MessageBox fallback (ErrorPanel was removed from UI but error calls remained)
- **HIGH FIX:** Scan completion shows proper success state (progress bar stays at 100%, status shows "Done" until next operation)
- **LOW FIX:** Status messages clean up automatically after 3 seconds (output location changes)
- Code files changed: 3 (ErrorViewModel, VirusTotalCommandHandler, SettingsHandler)
- Build: ✅ Clean, no errors or warnings

## v0.6.4
- **HIGH FIX:** Drag-to-reorder file list (users can control install order)
- **LOW FIX:** Compression Level Tooltips (explain speed/size tradeoffs)
- **LOW FIX:** Better UX clarity in Pack Settings panel
- **LOW FIX:** Deleted unused VirusTotalViewModel (dead code cleanup)
- Other bug fixes and improvements

## 0.6.3
- **HIGH FIX:** Stub installer refactor
- **LOW FIX:** Packaging reliability improvements
- **LOW FIX:** Stub execution pipeline stabilization
- Integrity verification improvements
- UI fixes
- Bug fixes