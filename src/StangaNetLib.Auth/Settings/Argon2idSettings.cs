using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for the Argon2id password hasher.</summary>
public sealed class Argon2idSettings
{
    /// <summary>Configuration section name. Value: <c>"Argon2idSettings"</c>.</summary>
    public const string SectionName = "Argon2idSettings";

    /// <summary>Memory cost in kibibytes. Default: 65536 (64 MiB).</summary>
    [Range(8, 4_194_304)]
    public int MemorySizeKb { get; set; } = 65_536;

    /// <summary>Number of iterations (time cost). Default: 3.</summary>
    [Range(1, 100)]
    public int Iterations { get; set; } = 3;

    /// <summary>Degree of parallelism. Default: 1.</summary>
    [Range(1, 16)]
    public int DegreeOfParallelism { get; set; } = 1;

    /// <summary>Salt length in bytes. Default: 16.</summary>
    [Range(8, 64)]
    public int SaltLengthBytes { get; set; } = 16;

    /// <summary>Derived hash length in bytes. Default: 32.</summary>
    [Range(16, 64)]
    public int HashLengthBytes { get; set; } = 32;
}
