// PackItPro/Services/ManifestValidator.cs
using PackItPro.Services;
using System;
using System.Collections.Generic;
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
        /// Validates a manifest and throws InvalidOperationException if any check fails.
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
                {
                    var file = manifest.Files[i];
                    ValidateManifestFile(file, i, errors);
                }

                // Install order must be unique and contiguous
                if (manifest.Files.Any(f => f.InstallOrder < 0))
                    errors.Add("All files must have non-negative install order.");

                var orders = manifest.Files.Select(f => f.InstallOrder).Distinct().OrderBy(x => x).ToList();
                if (orders.Count != manifest.Files.Count)
                    errors.Add("Install order values must be unique for each file.");

                for (int i = 0; i < orders.Count; i++)
                {
                    if (orders[i] != i)
                        errors.Add($"Install order must be contiguous (0, 1, 2...) — found gap at position {i}.");
                }
            }

            // Auto-update script reference
            if (!string.IsNullOrWhiteSpace(manifest.AutoUpdateScript))
            {
                if (!manifest.AutoUpdateScript.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                    errors.Add("AutoUpdateScript must be a .bat file.");

                // If winget updater is configured, the script should exist in the file list
                // (This is a warning, not an error, so we don't add it here)
            }

            // Checksum (optional but if present should be base64)
            if (!string.IsNullOrWhiteSpace(manifest.SHA256Checksum))
            {
                try
                {
                    Convert.FromBase64String(manifest.SHA256Checksum);
                }
                catch (FormatException)
                {
                    errors.Add("SHA256Checksum must be valid Base64 format.");
                }
            }

            if (errors.Count > 0)
                throw new InvalidOperationException(
                    $"Manifest validation failed:\n\n" + string.Join("\n", errors.Select(e => $"• {e}")));
        }

        private static void ValidateManifestFile(ManifestFile file, int index, List<string> errors)
        {
            if (file == null)
            {
                errors.Add($"File at index {index} is null.");
                return;
            }

            if (string.IsNullOrWhiteSpace(file.Name))
                errors.Add($"File {index}: Name is required.");

            if (string.IsNullOrWhiteSpace(file.InstallType))
                errors.Add($"File '{file.Name}': InstallType is required.");

            if (file.TimeoutMinutes <= 0)
                errors.Add($"File '{file.Name}': TimeoutMinutes must be positive (got {file.TimeoutMinutes}).");

            if (file.TimeoutMinutes > 120)
                errors.Add($"File '{file.Name}': TimeoutMinutes too large ({file.TimeoutMinutes} > 120).");

            if (string.IsNullOrWhiteSpace(file.DetectionSource))
                errors.Add($"File '{file.Name}': DetectionSource is required.");
        }

        /// <summary>
        /// Returns true if the manifest is valid, false otherwise.
        /// Does not throw.
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
