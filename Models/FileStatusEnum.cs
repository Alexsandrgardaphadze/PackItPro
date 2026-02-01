namespace PackItPro.Models
{
    public enum FileStatusEnum
    {
        Pending,
        Clean,
        Infected,
        ScanFailed,
        Skipped
    }

    public enum CompressionMethodEnum
    {
        Fast,
        Normal,
        Maximum
    }
}