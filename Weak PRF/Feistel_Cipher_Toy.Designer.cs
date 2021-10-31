
namespace FeistelToy
{
    partial class Feistel_Cipher_Toy
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.label1 = new System.Windows.Forms.Label();
            this.TextTB = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.RandomKeyTB = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.CipherTextTB = new System.Windows.Forms.TextBox();
            this.PlainTextTB = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.DPlainTextTB = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.ActionBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(13, 13);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(239, 50);
            this.label1.TabIndex = 0;
            this.label1.Text = "32 bytes long of message/\r\n32 characters of ASCII letters";
            // 
            // TextTB
            // 
            this.TextTB.Location = new System.Drawing.Point(13, 67);
            this.TextTB.Name = "TextTB";
            this.TextTB.Size = new System.Drawing.Size(356, 31);
            this.TextTB.TabIndex = 1;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 116);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(328, 25);
            this.label2.TabIndex = 2;
            this.label2.Text = "Random Key(System Random Generate)";
            // 
            // RandomKeyTB
            // 
            this.RandomKeyTB.Location = new System.Drawing.Point(13, 145);
            this.RandomKeyTB.Multiline = true;
            this.RandomKeyTB.Name = "RandomKeyTB";
            this.RandomKeyTB.ReadOnly = true;
            this.RandomKeyTB.Size = new System.Drawing.Size(356, 94);
            this.RandomKeyTB.TabIndex = 3;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 254);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(259, 25);
            this.label3.TabIndex = 4;
            this.label3.Text = "Encrypted Message/Cipher Text";
            // 
            // CipherTextTB
            // 
            this.CipherTextTB.Location = new System.Drawing.Point(13, 282);
            this.CipherTextTB.Multiline = true;
            this.CipherTextTB.Name = "CipherTextTB";
            this.CipherTextTB.ReadOnly = true;
            this.CipherTextTB.Size = new System.Drawing.Size(356, 94);
            this.CipherTextTB.TabIndex = 5;
            // 
            // PlainTextTB
            // 
            this.PlainTextTB.Location = new System.Drawing.Point(13, 420);
            this.PlainTextTB.Multiline = true;
            this.PlainTextTB.Name = "PlainTextTB";
            this.PlainTextTB.ReadOnly = true;
            this.PlainTextTB.Size = new System.Drawing.Size(356, 94);
            this.PlainTextTB.TabIndex = 7;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(12, 392);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(248, 25);
            this.label4.TabIndex = 6;
            this.label4.Text = "Decrypted Message/Plain Text";
            // 
            // DPlainTextTB
            // 
            this.DPlainTextTB.Location = new System.Drawing.Point(13, 560);
            this.DPlainTextTB.Multiline = true;
            this.DPlainTextTB.Name = "DPlainTextTB";
            this.DPlainTextTB.ReadOnly = true;
            this.DPlainTextTB.Size = new System.Drawing.Size(356, 94);
            this.DPlainTextTB.TabIndex = 9;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(12, 532);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(161, 25);
            this.label5.TabIndex = 8;
            this.label5.Text = "Decoded Plain Text";
            // 
            // ActionBTN
            // 
            this.ActionBTN.Location = new System.Drawing.Point(12, 661);
            this.ActionBTN.Name = "ActionBTN";
            this.ActionBTN.Size = new System.Drawing.Size(357, 54);
            this.ActionBTN.TabIndex = 10;
            this.ActionBTN.Text = "Encrypt/Decrypt";
            this.ActionBTN.UseVisualStyleBackColor = true;
            this.ActionBTN.Click += new System.EventHandler(this.ActionBTN_Click);
            // 
            // Feistel_Cipher_Toy
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(10F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 727);
            this.Controls.Add(this.ActionBTN);
            this.Controls.Add(this.DPlainTextTB);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.PlainTextTB);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.CipherTextTB);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.RandomKeyTB);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.TextTB);
            this.Controls.Add(this.label1);
            this.Name = "Feistel_Cipher_Toy";
            this.Text = "Feistel Cipher Toy";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox TextTB;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox RandomKeyTB;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox CipherTextTB;
        private System.Windows.Forms.TextBox PlainTextTB;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox DPlainTextTB;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Button ActionBTN;
    }
}

