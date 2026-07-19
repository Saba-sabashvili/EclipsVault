using System.Text;

namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// The associated data that ties a sealed payload to the one row it belongs in.
///
/// AES-GCM proves a blob has not been edited, but says nothing about <em>where</em> it came from.
/// Without this, anyone who can write the database can lift the ciphertext, wrapped DEK, key id and
/// algorithm out of one row and drop them into another, and the vault decrypts them without a
/// murmur. That is a privilege escalation from a single UPDATE: copy a production secret's envelope
/// over a development one you are cleared to read, then read it through the front door. It also
/// works backwards — drop an archived version's envelope onto the live secret and the credential
/// someone rotated away is quietly current again.
///
/// Binding the row's identity as associated data makes the payload only decryptable in the row it
/// was sealed for; anywhere else the tag check fails and the read is refused. Each shape gets its
/// own binding, so an archived value cannot stand in for a live one. Only immutable identity is
/// bound: names, projects and classifications change, and a reclassification must not be a
/// re-encryption.
/// </summary>
public static class SecretBinding
{
    /// <summary>The live value on a secret.</summary>
    public static byte[] ForCurrentValue(Guid secretId)
        => Encoding.UTF8.GetBytes($"eclipsvault:secret:v1:{secretId:D}");

    /// <summary>
    /// One archived value. The parent secret is bound too, so a version cannot be moved between
    /// secrets any more than it can be promoted to the live value of its own.
    /// </summary>
    public static byte[] ForArchivedVersion(Guid secretId, Guid versionId)
        => Encoding.UTF8.GetBytes($"eclipsvault:secret-version:v1:{secretId:D}:{versionId:D}");
}
