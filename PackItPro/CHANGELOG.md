# PackItPro — Changelog

## v0.7.3

### Fixes
- **Disclaimer now shows on every pack:** `AppSettings.DisclaimerAccepted` defaulted to
  `true`, meaning the disclaimer never appeared — not even once. Default changed to `false`.
  The "Do not show again" suppress path has been removed entirely; the disclaimer is a
  lightweight acknowledgement and is now shown unconditionally before every pack.
- **`out _` discard compile error fixed:** `PackagingCommandHandler` used `out _` for the
  `suppressFuture` parameter of `DisclaimerWindow.Show`. The compiler could not resolve the
  type and emitted `CS1503: cannot convert from 'out object' to 'out bool'`. Changed to
  `out bool _`.
- **`PackagingCommandHandler` memory leak fixed:** Three anonymous `PropertyChanged` lambdas
  on `FileList`, `Status`, and `Settings` were replaced with named methods so `Dispose()` can
  properly unsubscribe. Mirrors the fix previously applied to `FileOperationsHandler`.
- **Notes now passed through to `packitmeta.json`:** `PackagingCommandHandler` was still
  passing `filePaths: Items.Select(f => f.FilePath)` — per-file Notes were silently dropped.
  Now builds `List<ManifestGenerator.FileEntry>` with `FilePath + Notes`. `Packager` gained a
  `List<FileEntry>` primary overload; the `List<string>` overload delegates to it.
- **`VirusTotalCommandHandler` scan success calls `SetStatusSuccess`:** On a clean scan the
  handler set `_status.Message` directly, leaving `IsSuccess = false` and the progress bar
  not green. Now calls `SetStatusSuccess(scanSummary)` to match the pack flow.
- **`AppConstants.ExecutableExtensions` used everywhere:** `MainViewModel._executableExtensions`
  private `HashSet` replaced with `new HashSet<string>(AppConstants.ExecutableExtensions)`.
  `VirusTotalCommandHandler._executableExtensions` field removed — both extension filter loops
  now call `AppConstants.ExecutableExtensions.Contains` directly.
- **`CommandHandlerBase.RaiseCanExecuteChanged` now works:** Previously fired a dead event
  nobody subscribed to. Now calls `CommandManager.InvalidateRequerySuggested()` via
  `Dispatcher.BeginInvoke`, correctly invalidating all bound `RelayCommand`/`AsyncRelayCommand`
  instances.
- **`SettingsViewModel.LoadSettingsAsync` no longer drops three fields:** `MaxFilesInList`,
  `CompressionMethod`, and `DisclaimerAccepted` were omitted from the restore block, resetting
  to defaults on every app restart.
- **`ApplicationHandler.ExitCommand` async void fixed:** `RelayCommand(async _ => ...)` created
  an unobserved `async void` delegate — exceptions from `SaveSettingsAsync` would crash the
  process on exit. Switched to `AsyncRelayCommand`.
- **`AppConstants.FormatBytes` added:** Six private `FormatBytes` copies across
  `FileListViewModel`, `SummaryViewModel`, `SettingsHandler`, `UpdateAvailableWindow`,
  `CacheViewWindow`, and `App.xaml.cs` consolidated into one static method.
- **`SummaryPanel` status badge colour fixed:** Background was hardcoded to green regardless
  of `Status`. Added `DataTrigger`s for "⚠️ Infected Files" (red), "⚠️ Scan Errors" (amber),
  and "No Files" (grey).
- **`SummaryViewModel.AllScanned` trusted-file bug fixed:** `ScannedFiles` formula excluded
  `Trusted` files, so `AllScanned` was `false` even when all files were either scanned or
  explicitly trusted. Formula now: `CleanFiles + InfectedFiles + FailedScans + TrustedFiles`.
  `FileListViewModel` gains a `TrustedCount` property notified via `NotifyListChanged`.
- **`AlertDialog` detail box can no longer grow off-screen:** Long stack traces or paths now
  scroll inside a `MaxHeight="150"` `ScrollViewer` instead of pushing the window off the
  display edge.
- **`IsCancel` added to all dialogs:** `ConfirmDialog`, `AlertDialog`, `AboutWindow`,
  `FileAddResultWindow`, `ScanResultsWindow`, `PackItProSettingsWindow`, and
  `UpdateAvailableWindow` all gain `IsCancel="True"` on their dismiss/cancel buttons. ESC now
  closes every dialog in the app.
- **`VirusApiKeyWindow` buttons unstyled:** Both buttons used raw system chrome. Cancel now
  has the app's standard secondary style; Save uses `Win11Button` with `IsDefault="True"`.
- **`PackSettingsPanel` duplicate `ComboBoxItem` setter removed:** The `IsMouseOver` trigger
  had two `Background` setters — the first (`AppPrimaryColor`) was silently ignored; only
  `#2d2d44` is kept.
- **`ErrorPanel` animation flash fixed:** `ErrorBorder` now starts at `Opacity="0"` so the
  slide-in animation begins from invisible rather than flashing at full opacity first.
- **`ErrorPanel` `DropShadowEffect` frozen** — `po:Freeze="True"` added.
- **`StatusPanel` Pack Now button `DropShadowEffect` frozen** — `po:Freeze="True"` added.
- **`App.xaml.cs` hardcoded path strings replaced** with `AppConstants.AppName`,
  `AppConstants.CacheSubDir`, `AppConstants.LogsSubDir`, `AppConstants.CrashLogFileName`.
- **`AboutWindow` GitHub URL uses `AppConstants`** instead of a hardcoded literal.
- **`CacheViewWindow` private `FormatBytes` removed** — now calls `AppConstants.FormatBytes`.
- **`FileListPanel` "Maximum 20 files" label bound** to `MaxFilesInList` via `MultiBinding`
  `StringFormat` so it reflects the actual configured limit.

## v0.7.2

### New Features
- **Auto-Update System:** PackItPro can now download and install its own updates directly.
  `UpdateService` resolves the direct `.exe` asset from GitHub Releases, streams it to a temp
  file with progress reporting, then hands off to `UpdaterLauncher` which writes a PowerShell
  swap script, launches it hidden, and exits. The script waits for the process to exit, renames
  the temp file over the running exe (atomic on same drive), and restarts. A silent background
  check fires 8 seconds after startup and shows the dialog only if a newer version is available.
- **Packaging Disclaimer:** A `DisclaimerWindow` now appears before the first pack (suppressed
  after the user ticks "I understand"). Shows three permanent clauses (responsibility, legal use,
  scanning limitations) plus three contextual warning cards shown only when relevant: unscanned
  files, admin privileges requested, and infected files detected. Includes a live file summary
  strip (Files / Scanned / Unscanned / Infected / Trusted) so the user has full context.
  Accept button is disabled until the checkbox is ticked. ESC cancels. Persisted to
  `AppSettings.DisclaimerAccepted`.
- **SummaryPanel — Scan Coverage:** Two new rows added: "Scanned X / Y" (turns green when all
  files have scan results) and "VirusTotal Active/Off". The Total Files card now shows "X / Y"
  with a capacity progress bar.
- **AppConstants.cs:** All magic strings (file names, directory names, GitHub owner/repo,
  numeric limits) centralized in one file to prevent path drift across callsites.


### Fixes
- **`Assembly.Location` warning eliminated:** `UpdateService.DownloadUpdateAsync` and
  `UpdaterLauncher.GetCurrentExePath` now use `Environment.ProcessPath` (correct API for
  .NET 6+ single-file publish). `Assembly.GetExecutingAssembly().Location` always returns
  an empty string in single-file apps and triggered compiler warning IL3000.
- **VirusTotal scan progress bar no longer resets to 0% on success:** `VirusTotalCommandHandler`
  now calls `SetStatusReady()` only on failure or cancellation. On a clean scan completion the
  progress bar stays at 100%, consistent with how the pack flow behaves.
- **Per-file Notes now written into `packitmeta.json`:** `ManifestGenerator` gains a
  `FileEntry` record and a primary `Generate(List<FileEntry>)` overload. `PackagingCommandHandler`
  now passes `FilePath + Notes` instead of just `FilePath`. Empty notes are omitted from the
  JSON (`WhenWritingNull`). The old `List<string>` overload is kept as a backward-compatible
  delegate.
- **`ScanOnAdd` setting now persists:** `PackItProSettingsWindow` had no checkbox for
  `ScanOnAdd` — the setting existed in `AppSettings` and `SettingsViewModel` but was never
  exposed in the UI or written back by `SettingsHandler`. Checkbox added to the SECURITY
  section; `SettingsHandler` now writes `window.ScanOnAdd` back after save.
- **`FileOperationsHandler` — all `MessageBox.Show` calls replaced:** Browse skip feedback
  now uses `FileAddResultWindow` (consistent with the drag-and-drop path), "Clear all?"
  uses `ConfirmDialog`, export success/failure uses `AlertDialog`. Memory leak from anonymous
  `PropertyChanged` subscription also fixed with named method + `Dispose()` unsubscription.
- **`SummaryPanel` Status badge fixed:** The tinted background `Border` and the `TextBlock`
  were siblings in the same Grid cell — the Border rendered nearly invisible (Opacity 0.15)
  and the text floated on top unstyled. `TextBlock` is now a child of `Border` so the
  background correctly tints behind the text.
- **Top menu bar decluttered:** File counter pill ("0 / 20 files") and VirusTotal badge
  removed from the menu bar. Both pieces of information are now in SummaryPanel where
  they have context alongside the rest of the package stats.

### Notes for this release
- Auto-update download requires a `PackItPro.exe` asset attached to the GitHub Release.

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