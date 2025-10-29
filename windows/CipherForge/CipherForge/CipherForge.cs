using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace CipherForge
{
    public static class CipherForgeClass
    {
        // --- CONSTANTS ---
        private const int KEY_SIZE = 256;
        private const int SALT_SIZE = 16;
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE_BYTES = 16;
        private const int PBKDF2_ITERATIONS = 1000000;


        /// <summary>
        /// Derives a cryptographic key from a password and salt using PBKDF2 (SHA256).
        /// </summary>
        public static byte[] DeriveKey(string password, byte[] salt)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.");
            }
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PBKDF2_ITERATIONS, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(KEY_SIZE / 8);
            }
        }

        // --- STRING ENCRYPTION ROUTINE ---

        /// <summary>
        /// Encrypts an input string using AES-256 GCM and returns a Base64 encoded string.
        /// The output includes Salt, Nonce, and Auth Tag for secure decryption.
        /// </summary>
        /// <returns>A string formatted as: "CFV1:[Base64(Salt+Nonce+Ciphertext+Tag)]"</returns>
        public static string EncryptString(string plainText, string password)
        {
            if (string.IsNullOrEmpty(plainText) || string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Input string and password must be provided.");
            }

            byte[] keyBytes = null;
            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);

            try
            {
                // 1. Generate random salt and nonce
                byte[] salt = new byte[SALT_SIZE];
                byte[] nonce = new byte[NONCE_SIZE];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                    rng.GetBytes(nonce);
                }

                // 2. Derive Key
                keyBytes = DeriveKey(password, salt);

                // 3. Define Associated Authenticated Data (AAD)
                // Using the salt and nonce as AAD ensures integrity of the parameters.
                byte[] aad = new byte[salt.Length + nonce.Length];
                Buffer.BlockCopy(salt, 0, aad, 0, salt.Length);
                Buffer.BlockCopy(nonce, 0, aad, salt.Length, nonce.Length);

                // 4. Encrypt
                int cipherTextLength = inputBytes.Length;
                byte[] cipherTextWithTag = new byte[cipherTextLength + TAG_SIZE_BYTES];
                Span<byte> cipherTextSpan = cipherTextWithTag.AsSpan(0, cipherTextLength);
                Span<byte> tagSpan = cipherTextWithTag.AsSpan(cipherTextLength, TAG_SIZE_BYTES);

                using (var aesGcm = new AesGcm(keyBytes))
                {
                    aesGcm.Encrypt(nonce, inputBytes, cipherTextSpan, tagSpan, aad);
                }

                // 5. Combine metadata and ciphertext for output
                int totalLength = salt.Length + nonce.Length + cipherTextWithTag.Length;
                byte[] outputBytes = new byte[totalLength];

                Buffer.BlockCopy(salt, 0, outputBytes, 0, salt.Length);
                Buffer.BlockCopy(nonce, 0, outputBytes, salt.Length, nonce.Length);
                Buffer.BlockCopy(cipherTextWithTag, 0, outputBytes, salt.Length + nonce.Length, cipherTextWithTag.Length);

                // 6. Return Base64 encoded string with header
                return Convert.ToBase64String(outputBytes, Base64FormattingOptions.InsertLineBreaks);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("String encryption failed.", ex);
            }
            finally
            {
                if (keyBytes != null) Array.Fill(keyBytes, (byte)0);
            }
        }

        // --- STRING DECRYPTION ROUTINE ---

        /// <summary>
        /// Decrypts a Base64 encoded string encrypted with EncryptString.
        /// </summary>
        /// <returns>The original plain text string.</returns>
        public static string DecryptString(string encryptedText, string password)
        {
            if (string.IsNullOrEmpty(encryptedText) || string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Encrypted string and password must be provided.");
            }

            byte[] keyBytes = null;

            try
            {
                // 1. Decode Base64 and separate components
                byte[] inputBytes = Convert.FromBase64String(encryptedText);

                if (inputBytes.Length < SALT_SIZE + NONCE_SIZE + TAG_SIZE_BYTES)
                {
                    throw new FormatException("Input string is too short or corrupted.");
                }

                byte[] salt = inputBytes.Take(SALT_SIZE).ToArray();
                byte[] nonce = inputBytes.Skip(SALT_SIZE).Take(NONCE_SIZE).ToArray();
                byte[] cipherTextWithTag = inputBytes.Skip(SALT_SIZE + NONCE_SIZE).ToArray();

                // 2. Derive Key
                keyBytes = DeriveKey(password, salt);

                // 3. Define Associated Authenticated Data (AAD)
                byte[] aad = new byte[salt.Length + nonce.Length];
                Buffer.BlockCopy(salt, 0, aad, 0, salt.Length);
                Buffer.BlockCopy(nonce, 0, aad, salt.Length, nonce.Length);

                // 4. Decrypt and Authenticate
                int cipherTextLength = cipherTextWithTag.Length - TAG_SIZE_BYTES;
                byte[] plainTextBytes = new byte[cipherTextLength];

                Span<byte> cipherTextSpan = cipherTextWithTag.AsSpan(0, cipherTextLength);
                Span<byte> tagSpan = cipherTextWithTag.AsSpan(cipherTextLength, TAG_SIZE_BYTES);

                using (var aesGcm = new AesGcm(keyBytes))
                {
                    // Decrypt and validate tag against AAD. Throws CryptographicException on failure.
                    aesGcm.Decrypt(nonce, cipherTextSpan, tagSpan, plainTextBytes, aad);
                }

                // 5. Return decoded string
                return Encoding.UTF8.GetString(plainTextBytes);
            }
            catch (CryptographicException ex)
            {
                // Indicates wrong password or tampering
                throw new CryptographicException("Decryption failed. Incorrect password or corrupted data.", ex);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("String decryption failed.", ex);
            }
            finally
            {
                if (keyBytes != null) Array.Fill(keyBytes, (byte)0);
            }
        }
    }
}