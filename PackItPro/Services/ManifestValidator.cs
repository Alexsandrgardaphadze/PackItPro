// PackItPro/Services/ManifestValidator.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PackItPro.Services
{
    /// <summary>
    /// Validates that a generated manifest is safe and complete before packaging.
    /// Catches configuration errors early, preventing silent failures in the stub.
    /// </summary>
    public static class ManifestValidator
    {
        /// <summary>
        /// Validates a manifest and throws <see cref="InvalidOperationException"/>
        /// if any check fails.
        /// </summary>
        public static void Validate(PackageManifest manifest)
        {
            if (manifest == null)
                throw new ArgumentNullException(nameof(manifest));

            var errors = new List<string>();

            // Package name
            if (string.IsNullOrWhiteSpace(manifest.PackageName))
                errors.Add("Package name is required.");

            // Files list
            if (manifest.Files == null || manifest.Files.Count == 0)
                errors.Add("Package must contain at least one file.");

            // Individual file validation
            if (manifest.Files != null)
            {
                for (int i = 0; i < manifest.Files.Count; i++)
                    ValidateManifestFile(manifest.Files[i], i, errors);

                if (manifest.Files.Any(f => f.InstallOrder < 0))
                    errors.Add("All files must have non-negative install order.");

                var orders = manifest.Files.Select(f => f.InstallOrder).Distinct().OrderBy(x => x).ToList();
                if (orders.Count != manifest.Files.Count)
                    errors.Add("Install order values must be unique for each file.");

                for (int i = 0; i < orders.Count; i++)
                {
                    if (orders[i] != i)
                        errors.Add($"Install order must be contiguous (0, 1, 2…) — found gap at position {i}.");
                }
            }

            // Auto-update script reference
            if (!string.IsNullOrWhiteSpace(manifest.AutoUpdateScript))
            {
                if (!manifest.AutoUpdateScript.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                    errors.Add("AutoUpdateScript must be a .bat file.");
            }

            // Shortcuts (optional — validate only when present)
            if (manifest.Shortcuts != null)
            {
                for (int i = 0; i < manifest.Shortcuts.Count; i++)
                    ValidateShortcut(manifest.Shortcuts[i], i, errors);
            }

            // Checksum (optional, but must be valid Base64 when present)
            if (!string.IsNullOrWhiteSpace(manifest.SHA256Checksum))
            {
                try { Convert.FromBase64String(manifest.SHA256Checksum); }
                catch (FormatException)
                {
                    errors.Add("SHA256Checksum must be valid Base64 format.");
                }
            }

            if (errors.Count > 0)
                throw new InvalidOperationException(
                    "Manifest validation failed:\n\n" +
                    string.Join("\n", errors.Select(e => $"• {e}")));
        }

        private static void ValidateManifestFile(ManifestFile? file, int index, List<string> errors)
        {
            if (file == null) { errors.Add($"File at index {index} is null."); return; }

            if (string.IsNullOrWhiteSpace(file.Name))
                errors.Add($"File {index}: Name is required.");
            if (string.IsNullOrWhiteSpace(file.InstallType))
                errors.Add($"File '{file.Name}': InstallType is required.");
            if (file.TimeoutMinutes <= 0)
                errors.Add($"File '{file.Name}': TimeoutMinutes must be positive (got {file.TimeoutMinutes}).");
            if (file.TimeoutMinutes > 240)
                errors.Add($"File '{file.Name}': TimeoutMinutes too large ({file.TimeoutMinutes} > 240 max).");
            if (string.IsNullOrWhiteSpace(file.DetectionSource))
                errors.Add($"File '{file.Name}': DetectionSource is required.");
        }

        private static void ValidateShortcut(ManifestShortcut? shortcut, int index, List<string> errors)
        {
            if (shortcut == null) { errors.Add($"Shortcut at index {index} is null."); return; }

            if (string.IsNullOrWhiteSpace(shortcut.Name))
                errors.Add($"Shortcut {index}: Name is required.");

            if (string.IsNullOrWhiteSpace(shortcut.TargetPath))
                errors.Add($"Shortcut '{shortcut.Name}': TargetPath is required.");

            // Validate that the location string matches one of the known values.
            var validLocations = new[] { "Desktop", "StartMenu", "Startup" };
            if (!string.IsNullOrWhiteSpace(shortcut.Location) &&
                !validLocations.Contains(shortcut.Location, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add($"Shortcut '{shortcut.Name}': Location '{shortcut.Location}' is not valid. " +
                           $"Allowed values: {string.Join(", ", validLocations)}.");
            }

            // Warn when the target path contains characters that will fail at runtime.
            if (!string.IsNullOrWhiteSpace(shortcut.TargetPath))
            {
                char[] invalidChars = Path.GetInvalidPathChars();
                if (shortcut.TargetPath.Any(c => invalidChars.Contains(c)))
                    errors.Add($"Shortcut '{shortcut.Name}': TargetPath contains invalid path characters.");
            }
        }

        /// <summary>
        /// Returns true if the manifest is valid, false otherwise. Does not throw.
        /// </summary>
        public static bool TryValidate(PackageManifest manifest, out string? errorMessage)
        {
            try
            {
                Validate(manifest);
                errorMessage = null;
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }
    }
}