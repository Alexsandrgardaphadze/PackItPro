// StubInstaller/Core/StubShortcutCreator.cs
//
// No COM reference or NuGet package required.
// Uses IShellLinkW / IPersistFile directly via P/Invoke — works in any
// self-contained .NET 8 single-file publish without interop assemblies.
//
// ── Usage in Program.cs ───────────────────────────────────────────────────
// After your existing installer loop completes, add:
//
//   if (manifest.Shortcuts?.Count > 0)
//   {
//       Console.WriteLine("Creating shortcuts...");
//       StubShortcutCreator.CreateAll(manifest.Shortcuts, Console.WriteLine);
//   }
//
// ── Manifest.cs additions needed ─────────────────────────────────────────
// Add to PackageManifest:
//
//   [JsonPropertyName("shortcuts")]
//   public List<ManifestShortcut>? Shortcuts { get; set; }
//
// Add new class (matches what PackItPro serializes into packitmeta.json):
//
//   public class ManifestShortcut
//   {
//       [JsonPropertyName("name")]        public string  Name        { get; set; } = "";
//       [JsonPropertyName("targetPath")]  public string  TargetPath  { get; set; } = "";
//       [JsonPropertyName("arguments")]   public string? Arguments   { get; set; }
//       [JsonPropertyName("description")] public string? Description { get; set; }
//       [JsonPropertyName("location")]    public string  Location    { get; set; } = "Desktop";
//   }

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace StubInstaller
{
    /// <summary>
    /// Creates Windows shortcut (.lnk) files from the shortcut entries embedded
    /// in <c>packitmeta.json</c> by PackItPro at build time.
    /// Uses native COM P/Invoke — no IWshRuntimeLibrary reference needed.
    /// </summary>
    public static class StubShortcutCreator
    {
        // ── COM interface declarations ─────────────────────────────────────────
        // These are the raw Windows Shell COM interfaces. .NET's built-in COM
        // interop can consume them without a separate type library reference.

        [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
        private class ShellLink { }

        [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
         Guid("000214F9-0000-0000-C000-000000000046")]
        private interface IShellLinkW
        {
            void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile,
                         int cch, IntPtr pfd, uint fFlags);
            void GetIDList(out IntPtr ppidl);
            void SetIDList(IntPtr pidl);
            void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszName, int cch);
            void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
            void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszDir, int cch);
            void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
            void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszArgs, int cch);
            void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
            void GetHotkey(out short pwHotkey);
            void SetHotkey(short wHotkey);
            void GetShowCmd(out int piShowCmd);
            void SetShowCmd(int iShowCmd);
            void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszIconPath,
                                 int cch, out int piIcon);
            void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
            void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
            void Resolve(IntPtr hwnd, uint fFlags);
            void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
        }

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Creates every shortcut in <paramref name="shortcuts"/>.
        /// Individual failures are logged but do not abort the remaining entries.
        /// </summary>
        /// <param name="shortcuts">Shortcut list read from <c>packitmeta.json</c>.</param>
        /// <param name="log">Optional line logger (e.g. <c>Console.WriteLine</c>).</param>
        public static void CreateAll(
            IReadOnlyList<ManifestShortcut> shortcuts,
            Action<string>? log = null)
        {
            if (shortcuts == null || shortcuts.Count == 0) return;

            foreach (var entry in shortcuts)
            {
                try { CreateOne(entry, log); }
                catch (Exception ex)
                {
                    log?.Invoke($"[Shortcuts] WARN: could not create '{entry.Name}': {ex.Message}");
                }
            }
        }

        // ── Private ───────────────────────────────────────────────────────────

        private static void CreateOne(ManifestShortcut entry, Action<string>? log)
        {
            if (string.IsNullOrWhiteSpace(entry.Name) ||
                string.IsNullOrWhiteSpace(entry.TargetPath))
            {
                log?.Invoke("[Shortcuts] Skipping entry with empty name or target.");
                return;
            }

            string folder = ResolveFolder(entry.Location);
            string lnkPath = Path.Combine(folder, $"{SanitizeName(entry.Name)}.lnk");
            string expandedTarget = Environment.ExpandEnvironmentVariables(entry.TargetPath);

            // CoCreateInstance is handled by the [ComImport] attribute on ShellLink.
            var shellLink = (IShellLinkW)new ShellLink();
            var persistFile = (IPersistFile)shellLink;

            shellLink.SetPath(expandedTarget);
            shellLink.SetArguments(entry.Arguments ?? "");
            shellLink.SetDescription(entry.Description ?? "");

            if (File.Exists(expandedTarget))
            {
                shellLink.SetWorkingDirectory(Path.GetDirectoryName(expandedTarget) ?? "");
                shellLink.SetIconLocation(expandedTarget, 0);
            }

            // IPersistFile.Save persists the .lnk to disk.
            persistFile.Save(lnkPath, true);

            log?.Invoke($"[Shortcuts] Created: {lnkPath}");
        }

        private static string ResolveFolder(string? location) =>
            (location ?? "Desktop") switch
            {
                "StartMenu" => Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                "Startup" => Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                _ => Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };

        private static string SanitizeName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name.Trim();
        }
    }
}