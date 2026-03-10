### PackItPro — Changelog

## v0.7.0

- **Critical UI Fix:** Resolved invisible text issue in the "Output File Name" textbox within the settings panel. Text is now clearly visible with correct foreground and caret colors.
- **Improved Error Handling:** Enhanced error reporting in the stub installer. If an installer fails to launch or execute properly, a clear error message is displayed instead of silent failure.
- **UI Enhancements:** Updated the settings panel layout for better clarity and usability, ensuring all options are easily accessible and understandable.
- Other bug fixes and performance improvements.
- 
## v0.6.6 

- **CRITICAL FIX:** Merge conflict between two branches was resolved properly, and now everything from both of them is working correctly.

## v0.6.5
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