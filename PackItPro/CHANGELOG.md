# PackItPro — Changelog

## v0.7.1
- **New Feature — Per-File Notes:** Each file in the list now has an inline editable Notes column. Notes are displayed as a transparent input that looks like a label at rest and shows a border on hover/focus. Notes are persisted into `packitmeta.json` so the stub can display them during installation.
- **New Feature — Scan on Add:** New `ScanOnAdd` setting (off by default) automatically triggers a VirusTotal scan as soon as files are added via the browse dialog or drag-and-drop. Requires a valid API key and `ScanWithVirusTotal = true` — both are checked at call-time so API quota is never burned silently.
- **Fix — File List Layout:** The Delete (✕) button is now always visible regardless of window width. The Notes column stretches dynamically to fill all available space between the Status column and the Delete button (`SizeChanged` in code-behind). Previously, fixed-width columns summed past the panel's available share at default window size, clipping the delete button off-screen.
- **New Feature — FileStatusEnum.Trusted:** Added `Trusted` enum value for files whose hash is in TrustStore. Both converters (`FileStatusToColorConverter`, `StatusToBackgroundConverter`) now render trusted files in cyan-500 — visually distinct from `Clean` (emerald) so users can tell "trusted false positive" from "scanned and passed" at a glance.
- **Fix — UpdateService pre-release filter:** Switched from `/releases/latest` (single object, GitHub-controlled) to `/releases?per_page=30` with explicit client-side filtering of drafts and pre-releases. Version selection now uses `OrderByDescending` on parsed semantic version rather than relying on publish-date order.
- **Fix — TrustStore passed to VirusTotalCommandHandler:** Trusted files are now skipped before any API call is made. Previously every scan would re-flag files the user had already marked as false positives.
- **Fix — Duplicate file detection:** `AddFilesWithValidation` now rejects files already in the list (OrdinalIgnoreCase path comparison) before the `File.Exists` check. Reported as "Already in list: filename" in the skip results dialog.

## v0.7.0
- **Critical UI Fix:** Resolved invisible text issue in the "Output File Name" textbox within the settings panel. Text is now clearly visible with correct foreground and caret colors.
- **Improved Error Handling:** Enhanced error reporting in the stub installer. If an installer fails to launch or execute properly, a clear error message is displayed instead of silent failure.
- **UI Enhancements:** Updated the settings panel layout for better clarity and usability, ensuring all options are easily accessible and understandable.
- Other bug fixes and performance improvements.

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

## v0.6.3
- **HIGH FIX:** Stub installer refactor
- **LOW FIX:** Packaging reliability improvements
- **LOW FIX:** Stub execution pipeline stabilization
- Integrity verification improvements
- UI fixes
- Bug fixes