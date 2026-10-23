using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Tests;

public sealed class Argon2idPasswordHasherTests
{
    private static Argon2idPasswordHasher CreateSut()
        => new(Options.Create(new Argon2idSettings
        {
            MemorySizeKb = 8_192,
            Iterations = 2,
            DegreeOfParallelism = 1,
            SaltLengthBytes = 16,
            HashLengthBytes = 32,
        }));

    [Fact]
    public void Hash_Verify_RoundTrips()
    {
        var sut = CreateSut();
        var hash = sut.Hash("correct horse battery staple");

        hash.Should().StartWith("$argon2id$");
        sut.Verify("correct horse battery staple", hash).Should().BeTrue();
        sut.Verify("wrong", hash).Should().BeFalse();
    }

    [Fact]
    public void Hash_ProducesUniqueSalts()
    {
        var sut = CreateSut();
        sut.Hash("same").Should().NotBe(sut.Hash("same"));
    }
}
