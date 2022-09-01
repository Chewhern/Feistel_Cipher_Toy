using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ASodium;

namespace FeistelToy
{
    public partial class Feistel_Cipher_Toy : Form
    {
        public Feistel_Cipher_Toy()
        {
            InitializeComponent();
        }

        private void ActionBTN_Click(object sender, EventArgs e)
        {
            if (TextTB.Text.CompareTo("")!=0) 
            {
                String MessageText = TextTB.Text;
                Byte[] Message = Encoding.UTF8.GetBytes(MessageText);
                Byte[] Key = SodiumRNG.GetRandomBytes(32);
                Boolean IsMessage32Bytes = true;
                Byte[] CipherText = new Byte[] { };
                Byte[] PlainText = new Byte[] { };
                Byte[] Nonce = SodiumRNG.GetRandomBytes(32);
                Byte[] SecretMaterial = SodiumRNG.GetRandomBytes(128);
                if (Message.Length != 32) 
                {
                    IsMessage32Bytes = false;
                }
                if (IsMessage32Bytes == true) 
                {
                    CipherText = FeistelCore.Encrypt(Message, Nonce , SecretMaterial,Key);
                    PlainText = FeistelCore.Decrypt(CipherText, Nonce, SecretMaterial ,Key);
                    RandomKeyTB.Text = SodiumHelper.BinaryToHex(Key);
                    SecretMaterialTB.Text = SodiumHelper.BinaryToHex(SecretMaterial);
                    CipherTextTB.Text = SodiumHelper.BinaryToHex(CipherText);
                    NonceTB.Text = SodiumHelper.BinaryToHex(Nonce);
                    PlainTextTB.Text = SodiumHelper.BinaryToHex(PlainText);
                    DPlainTextTB.Text = Encoding.UTF8.GetString(PlainText);
                    SodiumSecureMemory.SecureClearBytes(Key);
                    SodiumSecureMemory.SecureClearBytes(SecretMaterial);
                }
                else 
                {
                    MessageBox.Show("Please enter message that's 32 bytes or 256 bits long or enter 32 English letters");
                }
            }
            else 
            {
                MessageBox.Show("Please enter any message to encrypt/decrypt");
            }
        }
    }
}
