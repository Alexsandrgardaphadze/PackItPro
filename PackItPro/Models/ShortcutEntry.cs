// PackItPro/Models/ShortcutEntry.cs
using System.Text.Json.Serialization;

namespace PackItPro.Models
{
    /// <summary>
    /// Describes a Windows shortcut (.lnk) that <c>StubInstaller</c> will
    /// create on the end-user's machine after all installers have run.
    /// Serialized into <c>packitmeta.json</c> under the <c>shortcuts</c> array.
    /// </summary>
    public class ShortcutEntry
    {
        /// <summary>
        /// Display name of the shortcut file (without the <c>.lnk</c> extension).
        /// Example: <c>"My App"</c> creates <c>My App.lnk</c>.
        /// </summary>
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        /// <summary>
        /// Path to the executable the shortcut points to.
        /// Supports environment variables, e.g. <c>%ProgramFiles%\MyApp\app.exe</c>.
        /// </summary>
        [JsonPropertyName("targetPath")]
        public string TargetPath { get; set; } = "";

        /// <summary>Optional arguments passed to the target when the shortcut is launched.</summary>
        [JsonPropertyName("arguments")]
        public string Arguments { get; set; } = "";

        /// <summary>Optional description shown in the shortcut's Properties dialog.</summary>
        [JsonPropertyName("description")]
        public string Description { get; set; } = "";

        /// <summary>
        /// Where to place the shortcut on the end-user's machine.
        /// Matches the values of <see cref="ShortcutLocation"/>.
        /// </summary>
        [JsonPropertyName("location")]
        public ShortcutLocation Location { get; set; } = ShortcutLocation.Desktop;
    }

    /// <summary>Placement options for a shortcut created by the stub installer.</summary>
    public enum ShortcutLocation
    {
        /// <summary>Current user's Desktop (<c>%USERPROFILE%\Desktop</c>).</summary>
        Desktop,

        /// <summary>Current user's Start Menu Programs folder.</summary>
        StartMenu,

        /// <summary>Current user's Startup folder (runs on Windows logon).</summary>
        Startup,
    }
}
