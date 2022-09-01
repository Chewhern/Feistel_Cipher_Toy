
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
            this.SecretMaterialTB = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.NonceTB = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(10, 10);
            this.label1.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(198, 40);
            this.label1.TabIndex = 0;
            this.label1.Text = "32 bytes long of message/\r\n32 characters of ASCII letters";
            // 
            // TextTB
            // 
            this.TextTB.Location = new System.Drawing.Point(10, 54);
            this.TextTB.Margin = new System.Windows.Forms.Padding(2);
            this.TextTB.Name = "TextTB";
            this.TextTB.Size = new System.Drawing.Size(350, 27);
            this.TextTB.TabIndex = 1;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(10, 93);
            this.label2.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(274, 20);
            this.label2.TabIndex = 2;
            this.label2.Text = "Random Key(System Random Generate)";
            // 
            // RandomKeyTB
            // 
            this.RandomKeyTB.Location = new System.Drawing.Point(10, 116);
            this.RandomKeyTB.Margin = new System.Windows.Forms.Padding(2);
            this.RandomKeyTB.Multiline = true;
            this.RandomKeyTB.Name = "RandomKeyTB";
            this.RandomKeyTB.ReadOnly = true;
            this.RandomKeyTB.Size = new System.Drawing.Size(350, 76);
            this.RandomKeyTB.TabIndex = 3;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(10, 316);
            this.label3.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(217, 20);
            this.label3.TabIndex = 4;
            this.label3.Text = "Encrypted Message/Cipher Text";
            // 
            // CipherTextTB
            // 
            this.CipherTextTB.Location = new System.Drawing.Point(10, 339);
            this.CipherTextTB.Margin = new System.Windows.Forms.Padding(2);
            this.CipherTextTB.Multiline = true;
            this.CipherTextTB.Name = "CipherTextTB";
            this.CipherTextTB.ReadOnly = true;
            this.CipherTextTB.Size = new System.Drawing.Size(350, 76);
            this.CipherTextTB.TabIndex = 5;
            // 
            // PlainTextTB
            // 
            this.PlainTextTB.Location = new System.Drawing.Point(10, 449);
            this.PlainTextTB.Margin = new System.Windows.Forms.Padding(2);
            this.PlainTextTB.Multiline = true;
            this.PlainTextTB.Name = "PlainTextTB";
            this.PlainTextTB.ReadOnly = true;
            this.PlainTextTB.Size = new System.Drawing.Size(350, 76);
            this.PlainTextTB.TabIndex = 7;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(10, 427);
            this.label4.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(209, 20);
            this.label4.TabIndex = 6;
            this.label4.Text = "Decrypted Message/Plain Text";
            // 
            // DPlainTextTB
            // 
            this.DPlainTextTB.Location = new System.Drawing.Point(10, 561);
            this.DPlainTextTB.Margin = new System.Windows.Forms.Padding(2);
            this.DPlainTextTB.Multiline = true;
            this.DPlainTextTB.Name = "DPlainTextTB";
            this.DPlainTextTB.ReadOnly = true;
            this.DPlainTextTB.Size = new System.Drawing.Size(350, 76);
            this.DPlainTextTB.TabIndex = 9;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(10, 539);
            this.label5.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(137, 20);
            this.label5.TabIndex = 8;
            this.label5.Text = "Decoded Plain Text";
            // 
            // ActionBTN
            // 
            this.ActionBTN.Location = new System.Drawing.Point(10, 642);
            this.ActionBTN.Margin = new System.Windows.Forms.Padding(2);
            this.ActionBTN.Name = "ActionBTN";
            this.ActionBTN.Size = new System.Drawing.Size(350, 43);
            this.ActionBTN.TabIndex = 10;
            this.ActionBTN.Text = "Encrypt/Decrypt";
            this.ActionBTN.UseVisualStyleBackColor = true;
            this.ActionBTN.Click += new System.EventHandler(this.ActionBTN_Click);
            // 
            // SecretMaterialTB
            // 
            this.SecretMaterialTB.Location = new System.Drawing.Point(10, 227);
            this.SecretMaterialTB.Margin = new System.Windows.Forms.Padding(2);
            this.SecretMaterialTB.Multiline = true;
            this.SecretMaterialTB.Name = "SecretMaterialTB";
            this.SecretMaterialTB.ReadOnly = true;
            this.SecretMaterialTB.Size = new System.Drawing.Size(350, 76);
            this.SecretMaterialTB.TabIndex = 12;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(10, 204);
            this.label6.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(350, 20);
            this.label6.TabIndex = 11;
            this.label6.Text = "Random Secret Material(System Random Generate)";
            // 
            // NonceTB
            // 
            this.NonceTB.Location = new System.Drawing.Point(471, 33);
            this.NonceTB.Margin = new System.Windows.Forms.Padding(2);
            this.NonceTB.Multiline = true;
            this.NonceTB.Name = "NonceTB";
            this.NonceTB.ReadOnly = true;
            this.NonceTB.Size = new System.Drawing.Size(350, 76);
            this.NonceTB.TabIndex = 14;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(471, 10);
            this.label7.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(297, 20);
            this.label7.TabIndex = 13;
            this.label7.Text = "Random Nonce (System Random Generate)";
            // 
            // Feistel_Cipher_Toy
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(917, 723);
            this.Controls.Add(this.NonceTB);
            this.Controls.Add(this.label7);
            this.Controls.Add(this.SecretMaterialTB);
            this.Controls.Add(this.label6);
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
            this.Margin = new System.Windows.Forms.Padding(2);
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
        private System.Windows.Forms.TextBox SecretMaterialTB;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.TextBox NonceTB;
        private System.Windows.Forms.Label label7;
    }
}

