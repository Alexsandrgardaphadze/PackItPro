// ViewModels/SummaryViewModel.cs
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace PackItPro.ViewModels
{
    public class SummaryViewModel : INotifyPropertyChanged
    {
        private readonly FileListViewModel _fileListViewModel;

        public SummaryViewModel(FileListViewModel fileListViewModel)
        {
            _fileListViewModel = fileListViewModel;
            // Subscribe to changes in the file list to update summary properties
            _fileListViewModel.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_fileListViewModel.Items) ||
                    e.PropertyName == nameof(_fileListViewModel.Count) ||
                    e.PropertyName == nameof(_fileListViewModel.CleanCount) ||
                    e.PropertyName == nameof(_fileListViewModel.InfectedCount) ||
                    e.PropertyName == nameof(_fileListViewModel.FailedCount) ||
                    e.PropertyName == nameof(_fileListViewModel.SkippedCount) ||
                    e.PropertyName == nameof(_fileListViewModel.TotalSize))
                {
                    OnPropertyChanged(nameof(Files));
                    OnPropertyChanged(nameof(CleanFiles));
                    OnPropertyChanged(nameof(InfectedFiles));
                    OnPropertyChanged(nameof(FailedScans));
                    OnPropertyChanged(nameof(SkippedFiles));
                    OnPropertyChanged(nameof(TotalSize));
                    OnPropertyChanged(nameof(Status));
                }
            };
        }

        // Properties derived from FileListViewModel
        public int Files => _fileListViewModel.Count;
        public long TotalSize => _fileListViewModel.TotalSize;
        public int CleanFiles => _fileListViewModel.CleanCount;
        public int InfectedFiles => _fileListViewModel.InfectedCount;
        public int FailedScans => _fileListViewModel.FailedCount;
        public int SkippedFiles => _fileListViewModel.SkippedCount;

        // NEW: Computed property for overall status based on file list
        public string Status => _fileListViewModel.HasInfectedFiles ?
            "⚠️ Infected Files" : "Ready";

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}