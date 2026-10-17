using FluentAssertions;
using StangaNetLib.Auth.Services;
using Xunit;

namespace StangaNetLib.Auth.Tests;

public sealed class PasswordHasherTests
{
    private static readonly PasswordHasher Sut = new();

    [Fact]
    public void Hash_SamePasswordProducesDifferentHashes()
    {
        // BCrypt embeds a random salt — each call produces a unique hash
        Sut.Hash("password123").Should().NotBe(Sut.Hash("password123"));
    }

    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        var hash = Sut.Hash("correct-horse-battery-staple");
        Sut.Verify("correct-horse-battery-staple", hash).Should().BeTrue();
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFalse()
    {
        var hash = Sut.Hash("correct-horse-battery-staple");
        Sut.Verify("wrong-password", hash).Should().BeFalse();
    }

    [Fact]
    public void Hash_DoesNotContainPlaintext()
    {
        const string pwd = "super-secret-password";
        Sut.Hash(pwd).Should().NotContain(pwd);
    }

    [Fact]
    public void Hash_ProducesNonEmptyString()
    {
        Sut.Hash("any-password").Should().NotBeNullOrEmpty();
    }
}
