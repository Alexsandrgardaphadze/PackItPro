// PackItPro/Services/CredentialStore.cs
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PackItPro.Services
{
    internal static class CredentialStore
    {
        // Stored next to settings.json, but encrypted — useless without the user's Windows account.
        private static readonly string StorePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PackItPro", "credentials.dat");

        // Entropy adds per-application uniqueness on top of the per-user DPAPI binding.
        // Changing this value invalidates all stored credentials (intentional for version breaks).
        private static readonly byte[] _entropy = Encoding.UTF8.GetBytes("PackItPro.VT.v1");

        internal static void SaveVirusTotalKey(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                if (File.Exists(StorePath))
                    File.Delete(StorePath);
                return;
            }

            byte[] plain = Encoding.UTF8.GetBytes(apiKey.Trim());
            byte[] encrypted = ProtectedData.Protect(plain, _entropy, DataProtectionScope.CurrentUser);

            Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);
            File.WriteAllBytes(StorePath, encrypted);

            Array.Clear(plain, 0, plain.Length);
        }

        /// <summary>
        /// Loads the VirusTotal API key. Returns null if not stored or decryption fails.
        /// Decryption failure (wrong user/machine) returns null rather than throwing.
        /// </summary>
        internal static string? LoadVirusTotalKey()
        {
            if (!File.Exists(StorePath))
                return null;

            try
            {
                byte[] encrypted = File.ReadAllBytes(StorePath);
                byte[] plain = ProtectedData.Unprotect(encrypted, _entropy, DataProtectionScope.CurrentUser);
                string key = Encoding.UTF8.GetString(plain);
                Array.Clear(plain, 0, plain.Length);
                return key;
            }
            catch (CryptographicException)
            {
                // Wrong user, wrong machine, or corrupted file — treat as missing
                return null;
            }
        }

        internal static bool HasStoredKey() => File.Exists(StorePath);
    }
}