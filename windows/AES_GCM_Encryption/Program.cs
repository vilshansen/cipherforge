// File: AES_GCM_Encryption/Program.cs
// This is the entry point for the Windows Forms application.
using System;
using System.Windows.Forms;

namespace AES_GCM_Encryption
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm()); // Run the main form
        }
    }
}
