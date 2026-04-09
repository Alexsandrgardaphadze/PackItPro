using System.Text.Json.Serialization;

namespace StubInstaller
{
    /// <summary>
    /// Represents a shortcut entry as defined in packitmeta.json.
    /// </summary>
    public class ManifestShortcut
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("targetPath")]
        public string TargetPath { get; set; } = "";

        [JsonPropertyName("arguments")]
        public string? Arguments { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("location")]
        public string Location { get; set; } = "Desktop";
    }
}