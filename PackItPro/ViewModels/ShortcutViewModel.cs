// PackItPro/ViewModels/ShortcutViewModel.cs
using PackItPro.Models;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// Editable wrapper around a single <see cref="ShortcutEntry"/>.
    /// Bound to rows in <c>ShortcutsPanel.xaml</c>.
    /// </summary>
    public class ShortcutViewModel : INotifyPropertyChanged
    {
        private string _name = "";
        private string _targetPath = "";
        private string _arguments = "";
        private string _description = "";
        private ShortcutLocation _location = ShortcutLocation.Desktop;

        /// <summary>Shortcut display name (without .lnk extension).</summary>
        public string Name
        {
            get => _name;
            set 
            { 
                _name = value ?? "";
                OnPropertyChanged();
                OnPropertyChanged(nameof(ValidationError));
            }
        }

        /// <summary>Full path to the target executable; supports %ENV% variables.</summary>
        public string TargetPath
        {
            get => _targetPath;
            set 
            { 
                _targetPath = value ?? "";
                OnPropertyChanged();
                OnPropertyChanged(nameof(ValidationError));
            }
        }

        /// <summary>Optional command-line arguments passed to the target.</summary>
        public string Arguments
        {
            get => _arguments;
            set { _arguments = value ?? ""; OnPropertyChanged(); }
        }

        /// <summary>Optional tooltip text shown in the shortcut's Properties dialog.</summary>
        public string Description
        {
            get => _description;
            set { _description = value ?? ""; OnPropertyChanged(); }
        }

        /// <summary>Destination folder on the end-user's machine.</summary>
        public ShortcutLocation Location
        {
            get => _location;
            set { _location = value; OnPropertyChanged(); }
        }

        /// <summary>Removes this row from the parent <see cref="ShortcutListViewModel"/>.</summary>
        public ICommand? RemoveCommand { get; set; }

        /// <summary>
        /// Validation error message displayed when required fields are incomplete.
        /// Returns empty string if all required fields are filled or row is empty.
        /// </summary>
        public string ValidationError
        {
            get
            {
                // Both Name and TargetPath are required if ANY field is filled
                bool hasAnyContent = !string.IsNullOrWhiteSpace(Name) ||
                                    !string.IsNullOrWhiteSpace(TargetPath) ||
                                    !string.IsNullOrWhiteSpace(Arguments) ||
                                    !string.IsNullOrWhiteSpace(Description);
                
                if (!hasAnyContent) return ""; // Row is empty — that's ok
                
                if (string.IsNullOrWhiteSpace(Name))
                    return "⚠️ Name is required";
                
                if (string.IsNullOrWhiteSpace(TargetPath))
                    return "⚠️ Target path is required";
                
                return ""; // All required fields filled
            }
        }

        /// <summary>Converts this view-model back to its serializable model.</summary>
        public ShortcutEntry ToModel() => new()
        {
            Name = Name.Trim(),
            TargetPath = TargetPath.Trim(),
            Arguments = Arguments.Trim(),
            Description = Description.Trim(),
            Location = Location,
        };

        /// <summary>Creates a view-model from an existing <see cref="ShortcutEntry"/>.</summary>
        public static ShortcutViewModel FromModel(ShortcutEntry entry) => new()
        {
            Name = entry.Name,
            TargetPath = entry.TargetPath,
            Arguments = entry.Arguments,
            Description = entry.Description,
            Location = entry.Location,
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}