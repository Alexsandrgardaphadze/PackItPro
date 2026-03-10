// PackItPro/ViewModels/CommandHandlers/MarkTrustCommandHandler.cs
using PackItPro.Models;
using PackItPro.Services;
using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    /// <summary>
    /// Handles trust management for file items.
    /// Lives on MainViewModel (not FileListViewModel) so the right-click context
    /// menu can reach these commands via ListView.Tag binding.
    /// </summary>
    public class MarkTrustCommandHandler : CommandHandlerBase
    {
        private readonly TrustStore _trustStore;
        private readonly ILogService _log;

        public ICommand MarkAsTrustedCommand { get; }
        public ICommand RemoveTrustCommand { get; }

        public MarkTrustCommandHandler(TrustStore trustStore, ILogService log)
        {
            _trustStore = trustStore ?? throw new ArgumentNullException(nameof(trustStore));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            MarkAsTrustedCommand = new AsyncRelayCommand(ExecuteMarkAsTrustedAsync, CanMark);
            RemoveTrustCommand = new AsyncRelayCommand(ExecuteRemoveTrustAsync, CanRemove);
        }

        private static bool CanMark(object? parameter) =>
            parameter is FileItemViewModel item && !item.IsTrustedFalsePositive;

        private static bool CanRemove(object? parameter) =>
            parameter is FileItemViewModel item && item.IsTrustedFalsePositive;

        private async Task ExecuteMarkAsTrustedAsync(object? parameter)
        {
            if (parameter is not FileItemViewModel item) return;

            // Guard: never allow overriding a trusted-engine detection
            if (item.FlaggedByTrustedEngine)
            {
                MessageBox.Show(
                    $"This file was flagged by a trusted security engine ({item.TrustedEngineName}).\n" +
                    "Trusted-engine detections cannot be overridden as a false positive.",
                    "Cannot Mark as Trusted",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            string hash = FileHasher.ComputeFileHashString(item.FilePath);
            // TrustStore.TrustAsync is the correct method name (not AddAsync)
            await _trustStore.TrustAsync(hash, item.FileName, "Marked as false positive by user");

            item.IsTrustedFalsePositive = true;
            item.Status = FileStatusEnum.Clean;
            _log.Info($"[Trust] '{item.FileName}' marked as trusted FP (hash={hash[..8]}…)");
        }

        private async Task ExecuteRemoveTrustAsync(object? parameter)
        {
            if (parameter is not FileItemViewModel item) return;

            string hash = FileHasher.ComputeFileHashString(item.FilePath);
            // TrustStore.UntrustAsync is the correct method name (not RemoveAsync)
            await _trustStore.UntrustAsync(hash);

            item.IsTrustedFalsePositive = false;
            // Revert to Pending — needs a fresh scan to verify
            item.Status = FileStatusEnum.Pending;
            _log.Info($"[Trust] Trust removed for '{item.FileName}' (hash={hash[..8]}…)");
        }
    }
}