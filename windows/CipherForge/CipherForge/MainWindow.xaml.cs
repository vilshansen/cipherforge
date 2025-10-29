using SecurePassphrase;
using System; // Required for Exception handling
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CipherForge
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        private const int NUM_WORDS_PASSPHRASE = 10; // Yields 129 bits of entropy from a list of 7,776 words
        public MainWindow()
        {
            InitializeComponent();

            // 1. Exception handling for initial passphrase generation
            try
            {
                // We use 5 words by default, but this could fail if the word list file isn't found
                string passphrase = PassphraseGenerator.Generate(NUM_WORDS_PASSPHRASE);
                TextBoxPassphrase.Text = passphrase;
                TextBoxOutput.Text = 
                "Welcome to CipherForge: A Secure Text Encryption Utility\n" +
                "\n" +
                "This desktop application is designed to securely encrypt and decrypt your text. We use established, standard cryptographic algorithms to guarantee your data's privacy, integrity, and authenticity.\n" +
                "\n" +
                "CipherForge uses Authenticated Encryption with Associated Data (AEAD), specifically AES-256 in Galois/Counter Mode (GCM), as its foundation.\n" +
                "\n" +
                "We never use your passphrase directly. Instead, we run it through the PBKDF2 (Password-Based Key Derivation Function 2) algorithm, using SHA256 and 1,000,000 iterations. This process derives a strong 256-bit (32-byte) key for AES-256. The 1,000,000 iterations significantly increase resistance against common brute-force attacks.\n" +
                "\n" +
                "AES-256-GCM is used because it not only encrypts the data but also authenticates it (tamper detection). For every operation, a unique 12-byte Nonce (Number Used Once) is generated to ensure the encryption is unique. The Salt and Nonce are combined to form the AAD (Associated Authenticated Data), which is securely bound to the ciphertext.\n" +
                "\n" +
                "The final encrypted result is a Base64 representation containing everything needed for decryption: the Salt, Nonce, Ciphertext, and the Authentication Tag.\n" +
                "\n" +
                "CipherForge includes a utility to generate high-entropy passphrases using a Diceware-style selection method. Words are loaded from an external file, and selection is guaranteed to be random, uniform, and bias-free thanks to the static method RandomNumberGenerator.GetInt32().";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Initialization Error: Could not generate passphrase. Check if 'diceware_wordlist.txt' is accessible. Details: {ex.Message}",
                                "Fatal Setup Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Error);
                // Optionally disable controls if initialization fails
                this.IsEnabled = false;
            }
        }

        private void ButtonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            // 2. Exception handling for Encryption
            try
            {
                string encrypted = CipherForgeClass.EncryptString(TextBoxOutput.Text, TextBoxPassphrase.Text);
                TextBoxOutput.Text = encrypted;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Encryption Failed: Please check your passphrase and input text. Details: {ex.Message}",
                                "Encryption Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Error);
            }
        }

        private void ButtonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // 3. Exception handling for Decryption
            try
            {
                // NOTE: Decryption will often fail if the passphrase is wrong (CryptographicException)
                string decrypted = CipherForgeClass.DecryptString(TextBoxOutput.Text, TextBoxPassphrase.Text);
                TextBoxOutput.Text = decrypted;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Decryption Failed: This usually means the passphrase is incorrect or the ciphertext is corrupted. Details: {ex.Message}",
                                "Decryption Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
            }
        }

        private void ButtonGeneratePassphrase_Click(object sender, RoutedEventArgs e)
        {
            // 4. Exception handling for button-triggered passphrase generation
            try
            {
                TextBoxPassphrase.Text = PassphraseGenerator.Generate(NUM_WORDS_PASSPHRASE);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Passphrase Generation Failed: Check the word list file. Details: {ex.Message}",
                                "Generation Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Error);
            }
        }
    }
}