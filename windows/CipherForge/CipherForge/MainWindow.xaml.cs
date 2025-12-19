using SecurePassphrase;
using System;
using System.Threading.Tasks;
using System.Windows;

namespace CipherForge
{
    public partial class MainWindow : Window
    {
        private const int NUM_WORDS_PASSPHRASE = 10;

        public MainWindow()
        {
            InitializeComponent();
            try
            {
                string passphrase = PassphraseGenerator.Generate(NUM_WORDS_PASSPHRASE);
                TextBoxPassphrase.Text = passphrase;
            }
            catch { /* Handle wordlist missing if necessary */ }
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
            try { TextBoxPassphrase.Text = PassphraseGenerator.Generate(NUM_WORDS_PASSPHRASE); }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Generation Error"); }
        }

        private void ButtonCopyPassphrase_Click(object sender, RoutedEventArgs e)
        {
            try { Clipboard.SetText(TextBoxPassphrase.Text); }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Copy Error"); }
        }
    }
}
