using SecurePassword;
using System;
using System.Threading.Tasks;
using System.Windows;

namespace CipherForge
{
    public partial class MainWindow : Window
    {
        private const int NUM_CHARACTERS_PASSWORD = 42;

        public MainWindow()
        {
            InitializeComponent();
#if DEBUG
            string passphrase = PasswordGenerator.Generate(NUM_CHARACTERS_PASSWORD);
            TextBoxPassphrase.Text = passphrase;
            TextBoxOutput.Text = "The convergence of mathematical precision and linguistic diversity is captured in equations like eⁱᴫ + 1 = 0 alongside geometric forms such as ⬡, ⟁, and ⦽.\n\nWhen data travels through the 'ether,' it often encounters multi-byte sequences like the Japanese ⚡プログラミング⚡ or the intricate curves of Devanagari script: नमस्ते दुनिया.\n\nEnsuring that the encryption buffer handles these without truncation is vital, especially when mixing standard ASCII with high-range symbols like 𝔖𝔬𝔪𝔢 𝔊𝔬𝔱𝔥𝔦𝔠 𝔗𝔢𝔵𝔱 and arrows like ⇄ ⇅ ⇆ ⇇ ⇈ ⇉ ⇊.\n\nIn the realm of globalized software, the application must gracefully manage the transition between the Cyrillic alphabet (Привет, как дела?) and the elegance of Arabic calligraphy (السلام عليكم).\n\nCryptographic integrity means that even a string of miscellaneous technical symbols—⌗, ⌧, ⌨, ⌬, ⍟—must be reproducible down to the last bit after decryption.\n\nFurthermore, testing the AcceptsReturn feature with line breaks between heavy-duty emojis like 🛸, 🧬, 🛡️, and 🗝️ ensures that the TextBox and the UTF-8 encoder are perfectly synced.\n\nFinally, by including Currency symbols from around the globe—€, £, ¥, ₹, ₿—and musical notation like ♩, ♪, ♫, ♬, the encryption logic is forced to process varying byte-lengths per character.\n\nIf the system can successfully encrypt this paragraph and return the exact same 100% accurate string, it confirms that the PBKDF2 key derivation and GCM mode are functioning with complete character-set transparency.";
#endif
        }

        private async void ButtonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            await RunSecureAction(async () =>
            {
                string plainText = TextBoxOutput.Text;
                string passphrase = TextBoxPassphrase.Text;

                string result = await Task.Run(() => CipherForgeClass.EncryptString(plainText, passphrase));
                TextBoxOutput.Text = result;
            }, "Encryption Failed");
        }

        private async void ButtonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            await RunSecureAction(async () =>
            {
                string encryptedText = TextBoxOutput.Text;
                string passphrase = TextBoxPassphrase.Text;

                string result = await Task.Run(() => CipherForgeClass.DecryptString(encryptedText, passphrase));
                TextBoxOutput.Text = result;
            }, "Decryption Failed");
        }

        private async Task RunSecureAction(Func<Task> action, string errorTitle)
        {
            try
            {
                MainUI.IsEnabled = false;
                LoadingOverlay.Visibility = Visibility.Visible;
                await action();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, errorTitle, MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                LoadingOverlay.Visibility = Visibility.Collapsed;
                MainUI.IsEnabled = true;
            }
        }

        private void ButtonGeneratePassphrase_Click(object sender, RoutedEventArgs e)
        {
            try { TextBoxPassphrase.Text = PasswordGenerator.Generate(NUM_CHARACTERS_PASSWORD); }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Generation Error"); }
        }

        private void ButtonCopyPassphrase_Click(object sender, RoutedEventArgs e)
        {
            try { Clipboard.SetText(TextBoxPassphrase.Text); }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Copy Error"); }
        }
    }
}
