// Views/SummaryPanel.xaml.cs - UPDATED VERSION
using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using PackItPro.ViewModels;

namespace PackItPro.Views
{
    /// <summary>
    /// Interaction logic for SummaryPanel.xaml
    /// Option A: Pure MVVM (Recommended) - Let bindings handle everything
    /// Option B: Code-behind - Manual UI updates (included below as alternative)
    /// </summary>
    public partial class SummaryPanel : UserControl
    {
        public SummaryPanel()
        {
            InitializeComponent();

            // ✅ OPTION A: Pure MVVM - No code needed, just use direct bindings in XAML
            // This is the recommended approach

            // ✅ OPTION B: If you want code-behind updates (uncomment below)
            // DataContextChanged += OnDataContextChanged;
        }

        // OPTION B IMPLEMENTATION (only if you choose code-behind approach)
        /*
        private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            // Unsubscribe from old ViewModel
            if (e.OldValue is SummaryViewModel oldVm)
            {
                oldVm.PropertyChanged -= OnViewModelPropertyChanged;
            }

            // Subscribe to new ViewModel
            if (e.NewValue is SummaryViewModel newVm)
            {
                newVm.PropertyChanged += OnViewModelPropertyChanged;
                UpdateUI(newVm);
            }
        }

        private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (sender is SummaryViewModel vm)
            {
                UpdateUI(vm);
            }
        }

        private void UpdateUI(SummaryViewModel vm)
        {
            FileCountTextBlock.Text = vm.Files.ToString();
            TotalSizeTextBlock.Text = FormatBytes(vm.TotalSize);
            CleanFilesTextBlock.Text = vm.CleanFiles.ToString();
            StatusTextBlock.Text = vm.Status;
            
            // Update estimated package size (rough estimate: 80% of total)
            PackageSizeTextBlock.Text = $"~{FormatBytes((long)(vm.TotalSize * 0.8))}";
            
            // Update estimated time (very rough: 1 second per MB)
            var estimatedSeconds = vm.TotalSize / (1024 * 1024);
            EstTimeTextBlock.Text = estimatedSeconds < 60 
                ? $"~{Math.Max(1, estimatedSeconds)} sec" 
                : $"~{Math.Max(1, estimatedSeconds / 60)} min";
            
            // Update requires admin from settings
            if (DataContext is MainViewModel mainVm)
            {
                RequiresAdminTextBlock.Text = mainVm.Settings.RequiresAdmin ? "Yes" : "No";
            }
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }
        */
    }
}
