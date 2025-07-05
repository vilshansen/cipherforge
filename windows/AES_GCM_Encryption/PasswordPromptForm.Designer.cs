namespace AES_GCM_Encryption
{
    partial class PasswordPromptForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            btnOk = new Button();
            tbPasswordInput = new TextBox();
            SuspendLayout();
            // 
            // btnOk
            // 
            btnOk.Location = new Point(360, 43);
            btnOk.Name = "btnOk";
            btnOk.Size = new Size(75, 23);
            btnOk.TabIndex = 2;
            btnOk.Text = "OK";
            btnOk.UseVisualStyleBackColor = true;
            btnOk.Click += btnOk_Click;
            // 
            // tbPasswordInput
            // 
            tbPasswordInput.Location = new Point(12, 12);
            tbPasswordInput.Name = "tbPasswordInput";
            tbPasswordInput.PlaceholderText = "(Enter or paste password for decryption here.)";
            tbPasswordInput.Size = new Size(423, 23);
            tbPasswordInput.TabIndex = 1;
            // 
            // PasswordPromptForm
            // 
            AcceptButton = btnOk;
            AccessibleName = "";
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(450, 78);
            Controls.Add(tbPasswordInput);
            Controls.Add(btnOk);
            Name = "PasswordPromptForm";
            StartPosition = FormStartPosition.CenterParent;
            Text = "Password for decryption";
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        public Button btnOk;
        private TextBox tbPasswordInput;
    }
}