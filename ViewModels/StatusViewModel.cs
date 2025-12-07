// ViewModels/StatusViewModel.cs
using System;
using System.ComponentModel;

namespace PackItPro.ViewModels
{
    public class StatusViewModel : INotifyPropertyChanged
    {
        private string _message = "Ready to pack files. Add files to continue.";
        private double _progressPercentage = 0.0;
        private bool _isPacking = false;
        private bool _isScanning = false;
        private string _operationName = "Idle";

        public string Message
        {
            get => _message;
            set { _message = value; OnPropertyChanged(); }
        }

        public double ProgressPercentage
        {
            get => _progressPercentage;
            set { _progressPercentage = value; OnPropertyChanged(); }
        }

        public bool IsPacking
        {
            get => _isPacking;
            set { _isPacking = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsBusy)); } // Update IsBusy when IsPacking changes
        }

        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsBusy)); } // Update IsBusy when IsScanning changes
        }

        // NEW: Computed property for overall busy state
        public bool IsBusy => IsPacking || IsScanning;

        public string OperationName
        {
            get => _operationName;
            set { _operationName = value; OnPropertyChanged(); }
        }

        // NEW: Helper methods for setting status based on operation
        public void SetStatusReady()
        {
            OperationName = "Idle";
            Message = "Ready to create .exe package";
            ProgressPercentage = 0;
            IsPacking = false;
            IsScanning = false;
        }

        public void SetStatusScanning()
        {
            OperationName = "Scanning";
            Message = "Scanning files with VirusTotal...";
            IsScanning = true;
            IsPacking = false; // Ensure packing flag is clear
        }

        public void SetStatusPacking()
        {
            OperationName = "Packing";
            Message = "Creating .exe package...";
            IsPacking = true;
            IsScanning = false; // Ensure scanning flag is clear
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}