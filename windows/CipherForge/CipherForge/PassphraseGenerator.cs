using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace SecurePassphrase
{
    public static class PassphraseGenerator
    {
        // 🚨 IMPORTANT: Replace this with the actual path to your word list file.
        private const string WordFilePath = "eff_large_wordlist.txt";

        private static string[] WordList;
        private static int DictionarySize;

        // Static constructor to load the word list only once.
        static PassphraseGenerator()
        {
            try
            {
                WordList = File.ReadAllLines(WordFilePath, Encoding.ASCII);
                DictionarySize = WordList.Length;

                if (DictionarySize < 512)
                {
                    Console.Error.WriteLine($"ERROR: Word list size is too small ({DictionarySize}). For security, a size of at least 512 is recommended.");
                    WordList = new string[0];
                    DictionarySize = 0;
                }
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine($"ERROR: Word list file not found at path: {WordFilePath}");
                WordList = new string[0];
                DictionarySize = 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR loading word list: {ex.Message}");
                WordList = new string[0];
                DictionarySize = 0;
            }
        }

        /// <summary>
        /// Generates a cryptographically secure passphrase composed of a specified number of random words.
        /// </summary>
        /// <param name="wordCount">The number of pseudo-English words to include in the passphrase.</param>
        /// <returns>A hyphen-separated string of random words.</returns>
        public static string Generate(int wordCount)
        {
            if (wordCount <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(wordCount), "Word count must be greater than zero.");
            }
            if (DictionarySize == 0)
            {
                throw new InvalidOperationException("The word list is empty or failed to load. Cannot generate passphrase.");
            }

            var passphrase = new StringBuilder();

            // 🔥 FIX: The call to RandomNumberGenerator.Create() is unnecessary and removed,
            // as GetInt32 is a static method and should be called directly on the type name.

            // We use a simple loop (no 'using' block needed now)
            for (int i = 0; i < wordCount; i++)
            {
                // KEY FIX: Call GetInt32 directly on the type name: RandomNumberGenerator.
                // This securely gets an index in the range [0, DictionarySize - 1].
                int index = RandomNumberGenerator.GetInt32(0, DictionarySize);

                if (i > 0)
                {
                    passphrase.Append("-");
                }
                passphrase.Append(WordList[index].Substring(6).Trim());
            }

            return passphrase.ToString();
        }
    }
}