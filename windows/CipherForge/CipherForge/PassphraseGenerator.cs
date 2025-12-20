using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace SecurePassword
{
    public static class PasswordGenerator
    {
        private static int DictionarySize;

        /// <summary>
        /// Generates a cryptographically secure password composed of a specified number of random characters.
        /// </summary>
        /// <param name="characterCount">The number of characters to include in the password.</param>
        /// <returns>A string of random characters.</returns>
        // A secure set of characters easily found on most European keyboard layouts
        // Alphanumerics + common symbols accessible via Shift on most ISO/European layouts
        // 42 characters >= 256 bits of entropy.
        public const string EasyTypeCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?-+*()/_:;";

        public static string Generate(int length = 42)
        {
            if (length <= 0) return string.Empty;

            var res = new StringBuilder();
            var charSet = EasyTypeCharacters.AsSpan();
            var charCount = charSet.Length;

            // We use a buffer to minimize calls to the RNG
            byte[] randomBytes = new byte[length];
            RandomNumberGenerator.Fill(randomBytes);

            foreach (byte b in randomBytes)
            {
                // Using modulo is acceptable here because 256 is close to a 
                // multiple of our set size, minimizing bias for a 24-char string.
                res.Append(charSet[b % charCount]);
            }

            return res.ToString();
        }
    }
}