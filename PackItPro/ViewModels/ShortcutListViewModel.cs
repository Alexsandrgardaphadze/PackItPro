// PackItPro/ViewModels/ShortcutListViewModel.cs
using PackItPro.Models;
using PackItPro.Views;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// Manages the list of shortcuts to be created by the stub installer.
    /// Exposed on <see cref="MainViewModel"/> and passed into
    /// <see cref="PackagingCommandHandler"/> at pack time.
    /// </summary>
    public class ShortcutListViewModel : INotifyPropertyChanged
    {
        private readonly ObservableCollection<ShortcutViewModel> _items = new();
        private ICommand? _closeCommand;

        /// <summary>Live collection of shortcut rows bound to the UI.</summary>
        public ObservableCollection<ShortcutViewModel> Items => _items;

        /// <summary>True when at least one shortcut has been defined.</summary>
        public bool HasShortcuts => _items.Any();

        // ── Commands ──────────────────────────────────────────────────────────

        /// <summary>Adds a blank shortcut row that the user fills in.</summary>
        public ICommand AddShortcutCommand { get; }

        /// <summary>Closes the Shortcuts Manager window.</summary>
        public ICommand CloseCommand
        {
            get => _closeCommand ?? new RelayCommand(_ => { });
            set => _closeCommand = value;
        }

        public ShortcutListViewModel()
        {
            AddShortcutCommand = new RelayCommand(_ => AddBlankInternal());
            CloseCommand = new RelayCommand(_ => { /* Handled by Window.Close() in code-behind */ });
            _items.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasShortcuts));
        }

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Returns all shortcuts as serializable models, filtering out any
        /// rows where the user left the name or target path blank.
        /// </summary>
        public System.Collections.Generic.List<ShortcutEntry> ToModelList() =>
            _items
                .Where(s => !string.IsNullOrWhiteSpace(s.Name)
                         && !string.IsNullOrWhiteSpace(s.TargetPath))
                .Select(s => s.ToModel())
                .ToList();

        /// <summary>Removes all shortcuts from the list.</summary>
        public void Clear() => _items.Clear();

        /// <summary>Public method to add a blank shortcut row from external commands.</summary>
        public void AddBlank()
        {
            AddBlankInternal();
        }

        // ── Private helpers ───────────────────────────────────────────────────

        private void AddBlankInternal()
        {
            var vm = new ShortcutViewModel();
            
            // Assign a RemoveCommand that shows a confirmation dialog
            // This prevents accidental deletion for keyboard users
            vm.RemoveCommand = new RelayCommand(_ =>
            {
                // Only show confirmation if the shortcut has been filled in
                bool hasContent = !string.IsNullOrWhiteSpace(vm.Name) ||
                                 !string.IsNullOrWhiteSpace(vm.TargetPath);
                
                if (hasContent)
                {
                    // User filled in data — show confirmation before deleting
                    bool confirmed = ConfirmDialog.Show(
                        Application.Current?.MainWindow,
                        title: "Delete Shortcut",
                        message: $"Remove '{vm.Name.Trim()}' from the list?",
                        confirmLabel: "Delete",
                        cancelLabel: "Cancel",
                        kind: ConfirmDialog.Kind.Warning);
                    
                    if (!confirmed) return; // User cancelled
                }
                
                // Deletion confirmed (or row was empty)
                _items.Remove(vm);
            });
            
            _items.Add(vm);
        }

        // ── INotifyPropertyChanged ────────────────────────────────────────────

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}