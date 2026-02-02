// ViewModels/Services/ILogService.cs
using System;
using System.Diagnostics;
using System.IO;

namespace PackItPro.ViewModels.Services
{
    public interface ILogService
    {
        void Error(string message, Exception ex);
        void Info(string message);
    }

    public class FileLogService : ILogService
    {
        private readonly string _logPath;
        public FileLogService(string logPath) => _logPath = logPath;

        public void Error(string message, Exception ex)
        {
            try
            {
                var entry = $"[{DateTime.Now:u}] ERROR: {message}\n{ex}\n\n";
                File.AppendAllText(_logPath, entry);
                Debug.WriteLine(entry);
            }
            catch { /* Silent fail */ }
        }

        public void Info(string message)
        {
            try
            {
                var entry = $"[{DateTime.Now:u}] INFO: {message}\n";
                File.AppendAllText(_logPath, entry);
                Debug.WriteLine(entry);
            }
            catch { /* Silent fail */ }
        }
    }
}