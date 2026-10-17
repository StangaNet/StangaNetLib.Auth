namespace StangaNetLib.Auth.Models;

/// <summary>Identifies the device that owns a refresh token.</summary>
/// <param name="DeviceId">Stable unique ID generated client-side (e.g. UUID stored in secure storage).</param>
/// <param name="DeviceName">Human-readable name (e.g. "iPhone 15 di Marco").</param>
/// <param name="Platform">Operating system / platform (e.g. "iOS", "Android", "Web").</param>
public sealed record DeviceInfo(
    string DeviceId,
    string DeviceName,
    string Platform);
