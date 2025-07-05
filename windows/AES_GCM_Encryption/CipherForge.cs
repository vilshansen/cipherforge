// File: AES_GCM_Encryption/CipherForge.cs
// This class contains the core encryption and decryption logic using AES-GCM.
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace AES_GCM_Encryption
{
    public static class CipherForge
    {
        // Constants matching the JavaScript version
        private const int KEY_SIZE_BYTES = 32; // 256-bit key for AES-GCM
        private const int TAG_SIZE_BYTES = 16; // Size of the authentication tag in AES-GCM
        private const int NONCE_SIZE_BYTES = 12; // Size of the nonce (IV) in AES-GCM
        private const int SALT_SIZE_BYTES = 16; // Size of the salt for PBKDF2 key derivation
        private const int PBKDF2_ITERATIONS = 1000000; // Increased iterations for better security
        private const int PASSWORD_LENGTH = 43; // Adjusted length for 256+ bits of entropy

        // ASCII Armoring Tags
        private const string START_TAG = "-----BEGIN AES-GCM ENCRYPTED DATA-----";
        private const string END_TAG = "-----END AES-GCM ENCRYPTED DATA-----";

        /// <summary>
        /// Generates a secure random password or uses a user-provided one.
        /// </summary>
        /// <param name="userProvided">Optional user-provided password.</param>
        /// <returns>The generated or provided password.</returns>
        public static string CreateSecurePassword(string userProvided = null)
        {
            if (!string.IsNullOrEmpty(userProvided))
            {
                if (userProvided.Length < 12)
                {
                    // In a real application, you might want to log this warning or display it to the user.
                    Console.WriteLine("Warning: Password is short. Consider a longer password.");
                }
                return userProvided;
            }

            // Expanded character pool for password generation
            const string characterPool = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ234566789!#%&?.-\\";
            var passwordChars = new char[PASSWORD_LENGTH];
            var randomBytes = new byte[PASSWORD_LENGTH];
            int characterPoolLength = characterPool.Length;

            for (int i = 0; i < PASSWORD_LENGTH; i++)
            {
                // Use GetInt32(maxValue) to get a cryptographically secure and unbiased random integer
                // within the range [0, maxValue - 1].
                passwordChars[i] = characterPool[RandomNumberGenerator.GetInt32(characterPoolLength)];
            }

            return new string(passwordChars);
        }

        /// <summary>
        /// Derives a cryptographic key from a password and salt using PBKDF2.
        /// </summary>
        /// <param name="password">The password to derive the key from.</param>
        /// <param name="salt">The salt to use for key derivation.</param>
        /// <returns>The derived key as a byte array.</returns>
        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PBKDF2_ITERATIONS, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(KEY_SIZE_BYTES);
            }
        }

        /// <summary>
        /// Encrypts plaintext using AES-GCM.
        /// </summary>
        /// <param name="plaintext">The text to encrypt.</param>
        /// <param name="userPassword">Optional user-provided password. If null, a secure password will be generated.</param>
        /// <returns>A tuple containing the ASCII armored ciphertext and the generated/used password.</returns>
        public static (string asciiArmored, string password) Encrypt(string plaintext, string userPassword = null)
        {
            if (string.IsNullOrEmpty(plaintext))
            {
                throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));
            }

            string password = CreateSecurePassword(userPassword);
            byte[] salt = new byte[SALT_SIZE_BYTES];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] key = DeriveKey(password, salt);
            byte[] nonce = new byte[NONCE_SIZE_BYTES];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }

            byte[] encryptedBytes;
            byte[] tag;

            using (AesGcm aesGcm = new AesGcm(key, TAG_SIZE_BYTES))
            {
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                encryptedBytes = new byte[plaintextBytes.Length];
                tag = new byte[TAG_SIZE_BYTES];

                aesGcm.Encrypt(nonce, plaintextBytes, encryptedBytes, tag);
            }

            // Combine salt, nonce, ciphertext, and tag
            byte[] combinedData = new byte[SALT_SIZE_BYTES + NONCE_SIZE_BYTES + encryptedBytes.Length + TAG_SIZE_BYTES];
            Buffer.BlockCopy(salt, 0, combinedData, 0, SALT_SIZE_BYTES);
            Buffer.BlockCopy(nonce, 0, combinedData, SALT_SIZE_BYTES, NONCE_SIZE_BYTES);
            Buffer.BlockCopy(encryptedBytes, 0, combinedData, SALT_SIZE_BYTES + NONCE_SIZE_BYTES, encryptedBytes.Length);
            Buffer.BlockCopy(tag, 0, combinedData, SALT_SIZE_BYTES + NONCE_SIZE_BYTES + encryptedBytes.Length, TAG_SIZE_BYTES);

            string encryptedDataB64 = Convert.ToBase64String(combinedData);
            string asciiArmored = $"{START_TAG}"+Environment.NewLine+$"{encryptedDataB64}"+Environment.NewLine+$"{END_TAG}";

            return (asciiArmored, password);
        }

        /// <summary>
        /// Decrypts AES-GCM ciphertext.
        /// </summary>
        /// <param name="asciiArmored">The ASCII armored ciphertext to decrypt.</param>
        /// <param name="password">The password used for encryption.</param>
        /// <returns>The decrypted plaintext.</returns>
        public static string Decrypt(string asciiArmored, string password)
        {
            if (string.IsNullOrEmpty(asciiArmored) || string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Encrypted data and password cannot be empty.");
            }

            string[] lines = asciiArmored.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
            int startIndex = -1;
            int endIndex = -1;

            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Trim() == START_TAG) startIndex = i;
                if (lines[i].Trim() == END_TAG) endIndex = i;
            }

            if (startIndex == -1 || endIndex == -1 || endIndex <= startIndex)
            {
                throw new FormatException("Invalid format: Start or end tag missing or incorrectly placed.");
            }

            string encryptedDataB64 = string.Join("", lines, startIndex + 1, endIndex - (startIndex + 1)).Trim();
            byte[] combinedData;
            try
            {
                combinedData = Convert.FromBase64String(encryptedDataB64);
            }
            catch (FormatException)
            {
                throw new FormatException("Invalid base64 data.");
            }

            if (combinedData.Length < SALT_SIZE_BYTES + NONCE_SIZE_BYTES + TAG_SIZE_BYTES)
            {
                throw new FormatException("Encrypted data is too short.");
            }

            byte[] salt = new byte[SALT_SIZE_BYTES];
            byte[] nonce = new byte[NONCE_SIZE_BYTES];
            byte[] tag = new byte[TAG_SIZE_BYTES];
            byte[] ciphertext;

            Buffer.BlockCopy(combinedData, 0, salt, 0, SALT_SIZE_BYTES);
            Buffer.BlockCopy(combinedData, SALT_SIZE_BYTES, nonce, 0, NONCE_SIZE_BYTES);

            int ciphertextLength = combinedData.Length - SALT_SIZE_BYTES - NONCE_SIZE_BYTES - TAG_SIZE_BYTES;
            if (ciphertextLength < 0)
            {
                throw new FormatException("Invalid data length for decryption.");
            }
            ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(combinedData, SALT_SIZE_BYTES + NONCE_SIZE_BYTES, ciphertext, 0, ciphertextLength);
            Buffer.BlockCopy(combinedData, SALT_SIZE_BYTES + NONCE_SIZE_BYTES + ciphertextLength, tag, 0, TAG_SIZE_BYTES);


            byte[] key = DeriveKey(password, salt);
            byte[] decryptedBytes = new byte[ciphertext.Length];

            using (var aesGcm = new AesGcm(key))
            {
                try
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes);
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException("Decryption failed. Incorrect password or corrupted data.", ex);
                }
            }

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
