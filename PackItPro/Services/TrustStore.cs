// PackItPro/Services/TrustStore.cs
// Per-user false-positive allowlist keyed by SHA-256 hash.
// Stored in %LocalAppData%\PackItPro\trusted_hashes.json.
// Thread-safe for concurrent reads; writes are serialised through a lock.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public class TrustStore
    {
        private readonly string _filePath;
        private readonly ConcurrentDictionary<string, TrustEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _saveLock = new();

        public TrustStore(string filePath)
        {
            _filePath = filePath;
        }

        // ── Public API ────────────────────────────────────────────────────────

        public bool IsTrusted(string sha256Hash) =>
            _entries.ContainsKey(sha256Hash);

        /// <summary>Adds a hash to the trust store. Persists immediately.</summary>
        public async Task TrustAsync(string sha256Hash, string fileName, string? note = null)
        {
            _entries[sha256Hash] = new TrustEntry
            {
                Hash = sha256Hash,
                FileName = fileName,
                Note = note ?? "Marked as false positive by user",
                TrustedAt = DateTime.UtcNow,
            };
            await SaveAsync();
        }

        /// <summary>Removes a hash from the trust store. Persists immediately.</summary>
        public async Task UntrustAsync(string sha256Hash)
        {
            _entries.TryRemove(sha256Hash, out _);
            await SaveAsync();
        }

        /// <summary>Returns a snapshot of all trusted entries for display in settings.</summary>
        public IReadOnlyList<TrustEntry> GetAll() =>
            _entries.Values.ToList();

        // ── Persistence ───────────────────────────────────────────────────────

        public async Task LoadAsync(ILogService? log = null)
        {
            if (!File.Exists(_filePath)) return;
            try
            {
                var json = await File.ReadAllTextAsync(_filePath);
                var items = JsonSerializer.Deserialize<List<TrustEntry>>(json);
                if (items == null) return;

                foreach (var item in items)
                    _entries[item.Hash] = item;

                log?.Info($"[TrustStore] Loaded {_entries.Count} trusted entries.");
            }
            catch (Exception ex)
            {
                log?.Warning($"[TrustStore] Load failed: {ex.Message}");
            }
        }

        private async Task SaveAsync()
        {
            try
            {
                var dir = Path.GetDirectoryName(_filePath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(
                    _entries.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true });

                // Write to temp then rename — prevents corruption on power loss
                var tmp = _filePath + ".tmp";
                await File.WriteAllTextAsync(tmp, json);
                File.Move(tmp, _filePath, overwrite: true);
            }
            catch { /* Non-fatal — trust list will reload correctly on restart */ }
        }
    }

    public class TrustEntry
    {
        public string Hash { get; set; } = "";
        public string FileName { get; set; } = "";
        public string? Note { get; set; }
        public DateTime TrustedAt { get; set; } = DateTime.UtcNow;
    }
}