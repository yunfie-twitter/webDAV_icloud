using System.Security.Cryptography;
using System.Text.Json;

const string KeyName = "iCloud-WebDAV-Primary-KEK-v1";
var provider = CngProvider.MicrosoftPlatformCryptoProvider;

CngKey OpenOrCreate()
{
    if (CngKey.Exists(KeyName, provider, CngKeyOpenOptions.MachineKey))
        return CngKey.Open(KeyName, provider, CngKeyOpenOptions.MachineKey);
    var creation = new CngKeyCreationParameters
    {
        Provider = provider,
        KeyCreationOptions = CngKeyCreationOptions.MachineKey,
        ExportPolicy = CngExportPolicies.None,
        KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing,
    };
    creation.Parameters.Add(
        new CngProperty("Length", BitConverter.GetBytes(3072), CngPropertyOptions.None)
    );
    return CngKey.Create(CngAlgorithm.Rsa, KeyName, creation);
}

string B64(byte[] value) => Convert.ToBase64String(value);
byte[] Unb64(JsonElement value) => Convert.FromBase64String(value.GetString()!);

try
{
    using var key = OpenOrCreate();
    using var rsa = new RSACng(key);
    var keyId = "cng-rsa-" + Convert.ToHexString(
        SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())
    ).ToLowerInvariant()[..24];
    using var input = JsonDocument.Parse(Console.In.ReadToEnd());
    var root = input.RootElement;
    var operation = root.GetProperty("operation").GetString();
    object result;
    switch (operation)
    {
        case "health":
            result = new
            {
                key_id = keyId,
                capabilities = new
                {
                    tier = 2,
                    tpm = true,
                    hardware_kek = true,
                    pcr_sealing = false,
                    attestation = "limited",
                    key_exportable_to_broker_memory = false,
                },
            };
            break;
        case "wrap":
            var context = Unb64(root.GetProperty("context"));
            var contextDigest = SHA256.HashData(context);
            var contextHash = Convert.ToHexString(contextDigest).ToLowerInvariant();
            var plaintextKey = Unb64(root.GetProperty("plaintext_key"));
            var boundPlaintext = new byte[contextDigest.Length + plaintextKey.Length];
            Buffer.BlockCopy(contextDigest, 0, boundPlaintext, 0, contextDigest.Length);
            Buffer.BlockCopy(
                plaintextKey, 0, boundPlaintext, contextDigest.Length, plaintextKey.Length
            );
            result = new
            {
                version = 1,
                key_id = keyId,
                algorithm = "RSA-OAEP-SHA256+CTX-SHA256",
                provider = "windows-cng",
                wrapped_key = B64(rsa.Encrypt(
                    boundPlaintext, RSAEncryptionPadding.OaepSHA256
                )),
                metadata = new { context_sha256 = contextHash },
            };
            CryptographicOperations.ZeroMemory(plaintextKey);
            CryptographicOperations.ZeroMemory(boundPlaintext);
            break;
        case "unwrap":
            var envelope = root.GetProperty("envelope");
            if (envelope.GetProperty("key_id").GetString() != keyId)
                throw new CryptographicException("Wrapped key belongs to another CNG key.");
            var requestedContext = Unb64(root.GetProperty("context"));
            var requestedHash = Convert.ToHexString(
                SHA256.HashData(requestedContext)
            ).ToLowerInvariant();
            if (envelope.GetProperty("metadata").GetProperty("context_sha256").GetString()
                != requestedHash)
                throw new CryptographicException("Wrapped key context mismatch.");
            var decrypted = rsa.Decrypt(
                Unb64(envelope.GetProperty("wrapped_key")),
                RSAEncryptionPadding.OaepSHA256
            );
            var requestedDigest = SHA256.HashData(requestedContext);
            if (decrypted.Length != requestedDigest.Length + 32
                || !CryptographicOperations.FixedTimeEquals(
                    decrypted.AsSpan(0, requestedDigest.Length), requestedDigest
                ))
                throw new CryptographicException("Wrapped key cryptographic context mismatch.");
            var recoveredKey = decrypted.AsSpan(requestedDigest.Length).ToArray();
            CryptographicOperations.ZeroMemory(decrypted);
            result = new
            {
                plaintext_key = B64(recoveredKey),
            };
            CryptographicOperations.ZeroMemory(recoveredKey);
            break;
        case "sign":
            result = new
            {
                key_id = keyId,
                algorithm = "RSA-PSS-SHA256",
                signature = B64(rsa.SignData(
                    Unb64(root.GetProperty("message")),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss
                )),
            };
            break;
        case "attest":
            throw new NotSupportedException(
                "Windows compatibility provider does not expose full TPM attestation."
            );
        default:
            throw new InvalidOperationException("Unknown operation.");
    }
    Console.Write(JsonSerializer.Serialize(new { ok = true, result }));
}
catch (Exception error)
{
    Console.Write(JsonSerializer.Serialize(new { ok = false, error = error.Message }));
    Environment.ExitCode = 1;
}
