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
        private bool _isSuccess = false;
        private string _operationName = "Idle";
        private DateTime? _operationStartTime;

        public string Message
        {
            get => _message;
            set { _message = value; OnPropertyChanged(); }
        }

        public double ProgressPercentage
        {
            get => _progressPercentage;
            set
            {
                // Clamp 0–100
                _progressPercentage = Math.Clamp(value, 0.0, 100.0);
                OnPropertyChanged();
            }
        }

        public bool IsPacking
        {
            get => _isPacking;
            set { _isPacking = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsBusy)); }
        }

        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsBusy)); }
        }

        /// <summary>True while any background operation is running.</summary>
        public bool IsBusy => IsPacking || IsScanning;

        /// <summary>
        /// True after a successful completion — lets the UI show a "done" state
        /// until the user starts a new operation.
        /// </summary>
        public bool IsSuccess
        {
            get => _isSuccess;
            set { _isSuccess = value; OnPropertyChanged(); }
        }

        public string OperationName
        {
            get => _operationName;
            set { _operationName = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// How many seconds the current (or last) operation has been running.
        /// Useful for "Elapsed: 12s" labels in the UI.
        /// </summary>
        public int ElapsedSeconds =>
            _operationStartTime.HasValue
                ? (int)(DateTime.Now - _operationStartTime.Value).TotalSeconds
                : 0;

        /// <summary>
        /// Resets to idle state. Call when the user starts a NEW operation (e.g. adds files),
        /// NOT after successful completion — use SetStatusSuccess() for that.
        /// Do NOT reset ProgressPercentage here; resetting in the finally block caused the
        /// progress bar to flash 100% → 0%. Progress resets when SetStatusPacking/Scanning begins.
        /// </summary>
        public void SetStatusReady()
        {
            OperationName = "Idle";
            Message = "Ready to create .exe package";
            IsPacking = false;
            IsScanning = false;
            IsSuccess = false;
            _operationStartTime = null;
        }

        /// <summary>
        /// Call this after a successful operation to hold the bar at 100%
        /// and show a "done" indicator in the UI.
        /// </summary>
        public void SetStatusSuccess(string? message = null)
        {
            IsPacking = false;
            IsScanning = false;
            IsSuccess = true;
            OperationName = "Done";
            ProgressPercentage = 100;
            Message = message ?? "Completed successfully!";
            _operationStartTime = null;
        }

        public void SetStatusScanning()
        {
            OperationName = "Scanning";
            Message = "Scanning files with VirusTotal...";
            ProgressPercentage = 0;
            IsScanning = true;
            IsPacking = false;
            IsSuccess = false;
            _operationStartTime = DateTime.Now;
        }

        public void SetStatusPacking()
        {
            OperationName = "Packing";
            Message = "Creating .exe package...";
            ProgressPercentage = 0;
            IsPacking = true;
            IsScanning = false;
            IsSuccess = false;
            _operationStartTime = DateTime.Now;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(
            [System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}