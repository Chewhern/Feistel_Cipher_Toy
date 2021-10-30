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
using System.Runtime.InteropServices;

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
                if (Message.Length != 32) 
                {
                    IsMessage32Bytes = false;
                }
                if (IsMessage32Bytes == true) 
                {
                    CipherText = FeistelCore.Encrypt(Message, Key);
                    PlainText = FeistelCore.Decrypt(CipherText, Key);
                    RandomKeyTB.Text = SodiumHelper.BinaryToHex(Key);
                    CipherTextTB.Text = SodiumHelper.BinaryToHex(CipherText);
                    PlainTextTB.Text = SodiumHelper.BinaryToHex(PlainText);
                    DPlainTextTB.Text = Encoding.UTF8.GetString(PlainText);
                    SodiumSecureMemory.SecureClearBytes(Key);
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

        private static Byte[] ConvertUIntToByteArray(uint Value)
        {
            return BitConverter.GetBytes(Value);
        }
    }
}
