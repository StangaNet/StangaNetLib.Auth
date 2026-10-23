using FluentAssertions;
using Microsoft.Extensions.Options;
using OtpNet;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Tests;

public sealed class TotpServiceTests
{
    private static TotpService CreateSut()
        => new(Options.Create(new TotpSettings
        {
            Issuer = "TestApp",
            VerificationWindow = 1,
            RecoveryCodeCount = 8,
            RecoveryCodeLength = 10,
        }));

    [Fact]
    public void GenerateSecret_And_Verify_CurrentCode()
    {
        var sut = CreateSut();
        var secret = sut.GenerateSecret();
        secret.Should().NotBeNullOrWhiteSpace();

        var totp = new Totp(Base32Encoding.ToBytes(secret));
        var code = totp.ComputeTotp();

        sut.Verify(secret, code).Should().BeTrue();
        sut.Verify(secret, "000000").Should().BeFalse();
    }

    [Fact]
    public void GetOtpAuthUri_ContainsIssuerAndAccount()
    {
        var sut = CreateSut();
        var secret = sut.GenerateSecret();
        var uri = sut.GetOtpAuthUri(secret, "user@example.com");

        uri.Should().StartWith("otpauth://totp/");
        uri.Should().Contain("TestApp");
        uri.Should().Contain("user");
    }

    [Fact]
    public void GenerateRecoveryCodes_ReturnsConfiguredCount()
    {
        var sut = CreateSut();
        var codes = sut.GenerateRecoveryCodes();
        codes.Should().HaveCount(8);
        codes.Should().OnlyContain(c => c.Length == 10);
        codes.Distinct().Should().HaveCount(8);
    }
}
