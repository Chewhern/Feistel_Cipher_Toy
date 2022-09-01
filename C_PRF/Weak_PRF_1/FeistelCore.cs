using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ASodium;
using BCASodium;
using System.Runtime.InteropServices;

namespace FeistelToy
{
    public static class FeistelCore
    {
        public static Byte[] Encrypt(Byte[] Message, Byte[] Nonce ,Byte[] SecretMaterial ,Byte[] Key,Boolean ClearKey=false) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null/empty");
            }
            else
            {
                if (Message.Length != 32)
                {
                    throw new ArgumentException("Error: Message must exactly be 32 bytes in length");
                }
            }
            Byte[] LeftMessage = new Byte[16];
            Byte[] RightMessage = new Byte[16];
            Byte[] PreviousSubKey = new Byte[16];
            Byte[] CipherText = new Byte[] { };
            Byte[] SubKey = new Byte[] { };
            Byte[] RoundKey = new Byte[] { };
            Byte[] EncryptedNonce = new Byte[] { };
            Byte[] SubEncryptedNonce1 = new Byte[16];
            Byte[] SubEncryptedNonce2 = new Byte[16];
            Byte[] Salt = new Byte[SodiumPasswordHashArgon2.GetSaltBytesLength()];
            Byte[] ActualCipherText = new Byte[] { };
            int Count = 128;
            int Loop = 0;
            int LoopCount = 0;
            Array.Copy(Message, 0, LeftMessage, 0, 16);
            Array.Copy(Message, 16, RightMessage, 0, 16);
            while (LoopCount < Count) 
            {
                while (Loop < Salt.Length)
                {
                    Salt[Loop] += 1;
                    Loop += 1;
                }
                Loop = 0;
                if (LoopCount == 0) 
                {
                    SubKey = SodiumPasswordHashArgon2.Argon2PBKDFCustom(32, Key, Salt,1,8192);
                }
                else 
                {
                    PreviousSubKey = SubKey;
                    SubKey = SodiumPasswordHashArgon2.Argon2PBKDFCustom(32, Key, Salt, 1, 8192);
                    SodiumSecureMemory.SecureClearBytes(PreviousSubKey);
                }
                RoundKey = GenerateRoundKey(SubKey,SecretMaterial);
                EncryptedNonce = GenerateEncryptedNonce(RightMessage, Nonce , SecretMaterial ,RoundKey);
                Array.Copy(EncryptedNonce, 0, SubEncryptedNonce1, 0, 16);
                Array.Copy(EncryptedNonce, 16, SubEncryptedNonce2, 0, 16);
                CipherText = FRXOR(LeftMessage, SubEncryptedNonce1);
                CipherText = FRXOR(CipherText, SubEncryptedNonce2);
                LeftMessage = RightMessage;
                RightMessage = CipherText;
                SodiumSecureMemory.SecureClearBytes(RoundKey);
                SodiumSecureMemory.SecureClearBytes(EncryptedNonce);
                SodiumSecureMemory.SecureClearBytes(SubEncryptedNonce1);
                SodiumSecureMemory.SecureClearBytes(SubEncryptedNonce2);
                LoopCount += 1;
            }
            SodiumSecureMemory.SecureClearBytes(SubKey);
            ActualCipherText = RightMessage.Concat(LeftMessage).ToArray();
            SodiumSecureMemory.SecureClearBytes(LeftMessage);
            SodiumSecureMemory.SecureClearBytes(RightMessage);
            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return ActualCipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] SecretMaterial, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text can't be null/empty");
            }
            else
            {
                if (CipherText.Length != 32)
                {
                    throw new ArgumentException("Error: Cipher Text must exactly be 32 bytes in length");
                }
            }
            Byte[] LeftMessage = new Byte[16];
            Byte[] RightMessage = new Byte[16];
            Byte[] PreviousSubKey = new Byte[16];
            Byte[] Buff = new Byte[] { };
            Byte[] SubKey = new Byte[] { };
            Byte[] RoundKey = new Byte[] { };
            Byte[] EncryptedNonce = new Byte[] { };
            Byte[] SubEncryptedNonce1 = new Byte[16];
            Byte[] SubEncryptedNonce2 = new Byte[16];
            Byte[] Salt = new Byte[SodiumPasswordHashArgon2.GetSaltBytesLength()];
            Byte[] ActualBuff = new Byte[] { };
            Byte Count = 128;
            int Loop = 0;
            int LoopCount = 0;
            Array.Copy(CipherText, 0, LeftMessage, 0, 16);
            Array.Copy(CipherText, 16, RightMessage, 0, 16);
            while (Count >=1)
            {
                while (Loop < Salt.Length)
                {
                    Salt[Loop] = Count;
                    Loop += 1;
                }
                Loop = 0;
                if (LoopCount == 0)
                {
                    SubKey = SodiumPasswordHashArgon2.Argon2PBKDFCustom(32, Key, Salt, 1, 8192);
                }
                else
                {
                    PreviousSubKey = SubKey;
                    SubKey = SodiumPasswordHashArgon2.Argon2PBKDFCustom(32, Key, Salt, 1, 8192);
                    SodiumSecureMemory.SecureClearBytes(PreviousSubKey);
                }
                RoundKey = GenerateRoundKey(SubKey, SecretMaterial);
                EncryptedNonce = GenerateEncryptedNonce(RightMessage, Nonce, SecretMaterial, RoundKey);
                Array.Copy(EncryptedNonce, 0, SubEncryptedNonce1, 0, 16);
                Array.Copy(EncryptedNonce, 16, SubEncryptedNonce2, 0, 16);
                Buff = FRXOR(LeftMessage, SubEncryptedNonce1);
                Buff = FRXOR(Buff, SubEncryptedNonce2);
                LeftMessage = RightMessage;
                RightMessage = Buff;
                SodiumSecureMemory.SecureClearBytes(RoundKey);
                SodiumSecureMemory.SecureClearBytes(EncryptedNonce);
                SodiumSecureMemory.SecureClearBytes(SubEncryptedNonce1);
                SodiumSecureMemory.SecureClearBytes(SubEncryptedNonce2);
                Count -= 1;
                LoopCount += 1;
            }
            SodiumSecureMemory.SecureClearBytes(SubKey);
            ActualBuff = RightMessage.Concat(LeftMessage).ToArray();
            SodiumSecureMemory.SecureClearBytes(LeftMessage);
            SodiumSecureMemory.SecureClearBytes(RightMessage);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(SecretMaterial);
            }
            return ActualBuff;
        }

        public static Byte[] GenerateEncryptedNonce(Byte[] Message, Byte[] Nonce, Byte[] SecretMaterial ,Byte[] Key) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message can't be null/empty");
            }
            else 
            {
                if (Message.Length != 16) 
                {
                    throw new ArgumentException("Error: Message must exactly be 16 bytes in length");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else
            {
                if (Key.Length != 32)
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes in length");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            else
            {
                if (Key.Length != 32)
                {
                    throw new ArgumentException("Error: Nonce must exactly be 32 bytes in length");
                }
            }
            Byte[] EncryptedNonce = new Byte[] { };
            Byte[] RoundKey = new Byte[] { };
            RoundKey = GenerateRoundKey(Key,SecretMaterial);
            EncryptedNonce = FRXOR(RoundKey, Nonce);
            SodiumSecureMemory.SecureClearBytes(RoundKey);
            return EncryptedNonce;
        }

        public static Byte[] GenerateRoundKey(Byte[] Key, Byte[] SecretMaterial)
        {
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else
            {
                if (Key.Length != 32)
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes in length");
                }
            }
            if (SecretMaterial.Length != 128)
            {
                throw new ArgumentException("Error: Secret Material must exactly be 128 bytes in length");
            }
            Byte[] SubSecretMaterial1 = new Byte[32];
            Byte[] SubSecretMaterial2 = new Byte[32];
            Byte[] SubSecretMaterial3 = new Byte[32];
            Byte[] SubSecretMaterial4 = new Byte[32];
            Byte[] PublicConstant1 = SodiumHelper.HexToBinary("bcf1d10bee99f18fde9ac7bbde8d4016f6b31b47c01a88e42d762de9ed21b3a2");
            Byte[] PublicConstant2 = SodiumHelper.HexToBinary("c0e0c85c516fc27080d56dee5a5b0070d41c986addc3dabfd50284444dc9b347");
            Byte[] PublicConstant3 = SodiumHelper.HexToBinary("82cf0e329b737d9907133b3e27991bbe18eae6d8cab447fe9fa885f3faf3b0b8");
            Byte[] PublicConstant4 = SodiumHelper.HexToBinary("f25482e1c6c97bbed245d17fc8f3024ebf4ae4f067501b8a2e26fb0a023763eb");
            Byte[] TempKey1 = new Byte[4];
            Byte[] TempKey2 = new Byte[4];
            Byte[] TempKey3 = new Byte[4];
            Byte[] TempKey4 = new Byte[4];
            Byte[] TempKey5 = new Byte[4];
            Byte[] TempKey6 = new Byte[4];
            Byte[] TempKey7 = new Byte[4];
            Byte[] TempKey8 = new Byte[4];
            uint[] SubKeyUInt1 = new uint[2];
            uint[] SubKeyUInt2 = new uint[2];
            uint[] SubKeyUInt3 = new uint[2];
            uint[] SubKeyUInt4 = new uint[2];
            Byte[] TempSubSecretMaterial1 = new Byte[4];
            Byte[] TempSubSecretMaterial2 = new Byte[4];
            Byte[] TempSubSecretMaterial3 = new Byte[4];
            Byte[] TempSubSecretMaterial4 = new Byte[4];
            Byte[] TempSubSecretMaterial5 = new Byte[4];
            Byte[] TempSubSecretMaterial6 = new Byte[4];
            Byte[] TempSubSecretMaterial7 = new Byte[4];
            Byte[] TempSubSecretMaterial8 = new Byte[4];
            Byte[] TempSubSecretMaterial9 = new Byte[4];
            Byte[] TempSubSecretMaterial10 = new Byte[4];
            Byte[] TempSubSecretMaterial11 = new Byte[4];
            Byte[] TempSubSecretMaterial12 = new Byte[4];
            Byte[] TempSubSecretMaterial13 = new Byte[4];
            Byte[] TempSubSecretMaterial14 = new Byte[4];
            Byte[] TempSubSecretMaterial15 = new Byte[4];
            Byte[] TempSubSecretMaterial16 = new Byte[4];
            Byte[] TempSubSecretMaterial17 = new Byte[4];
            Byte[] TempSubSecretMaterial18 = new Byte[4];
            Byte[] TempSubSecretMaterial19 = new Byte[4];
            Byte[] TempSubSecretMaterial20 = new Byte[4];
            Byte[] TempSubSecretMaterial21 = new Byte[4];
            Byte[] TempSubSecretMaterial22 = new Byte[4];
            Byte[] TempSubSecretMaterial23 = new Byte[4];
            Byte[] TempSubSecretMaterial24 = new Byte[4];
            Byte[] TempSubSecretMaterial25 = new Byte[4];
            Byte[] TempSubSecretMaterial26 = new Byte[4];
            Byte[] TempSubSecretMaterial27 = new Byte[4];
            Byte[] TempSubSecretMaterial28 = new Byte[4];
            Byte[] TempSubSecretMaterial29 = new Byte[4];
            Byte[] TempSubSecretMaterial30 = new Byte[4];
            Byte[] TempSubSecretMaterial31 = new Byte[4];
            Byte[] TempSubSecretMaterial32 = new Byte[4];
            uint[] SubSecretMaterialUInt1 = new uint[2];
            uint[] SubSecretMaterialUInt2 = new uint[2];
            uint[] SubSecretMaterialUInt3 = new uint[2];
            uint[] SubSecretMaterialUInt4 = new uint[2];
            uint[] SubSecretMaterialUInt5 = new uint[2];
            uint[] SubSecretMaterialUInt6 = new uint[2];
            uint[] SubSecretMaterialUInt7 = new uint[2];
            uint[] SubSecretMaterialUInt8 = new uint[2];
            uint[] SubSecretMaterialUInt9 = new uint[2];
            uint[] SubSecretMaterialUInt10 = new uint[2];
            uint[] SubSecretMaterialUInt11 = new uint[2];
            uint[] SubSecretMaterialUInt12 = new uint[2];
            uint[] SubSecretMaterialUInt13 = new uint[2];
            uint[] SubSecretMaterialUInt14 = new uint[2];
            uint[] SubSecretMaterialUInt15 = new uint[2];
            uint[] SubSecretMaterialUInt16 = new uint[2];
            Byte[] TempPublicConstant1 = new Byte[4];
            Byte[] TempPublicConstant2 = new Byte[4];
            Byte[] TempPublicConstant3 = new Byte[4];
            Byte[] TempPublicConstant4 = new Byte[4];
            Byte[] TempPublicConstant5 = new Byte[4];
            Byte[] TempPublicConstant6 = new Byte[4];
            Byte[] TempPublicConstant7 = new Byte[4];
            Byte[] TempPublicConstant8 = new Byte[4];
            Byte[] TempPublicConstant9 = new Byte[4];
            Byte[] TempPublicConstant10 = new Byte[4];
            Byte[] TempPublicConstant11 = new Byte[4];
            Byte[] TempPublicConstant12 = new Byte[4];
            Byte[] TempPublicConstant13 = new Byte[4];
            Byte[] TempPublicConstant14 = new Byte[4];
            Byte[] TempPublicConstant15 = new Byte[4];
            Byte[] TempPublicConstant16 = new Byte[4];
            Byte[] TempPublicConstant17 = new Byte[4];
            Byte[] TempPublicConstant18 = new Byte[4];
            Byte[] TempPublicConstant19 = new Byte[4];
            Byte[] TempPublicConstant20 = new Byte[4];
            Byte[] TempPublicConstant21 = new Byte[4];
            Byte[] TempPublicConstant22 = new Byte[4];
            Byte[] TempPublicConstant23 = new Byte[4];
            Byte[] TempPublicConstant24 = new Byte[4];
            Byte[] TempPublicConstant25 = new Byte[4];
            Byte[] TempPublicConstant26 = new Byte[4];
            Byte[] TempPublicConstant27 = new Byte[4];
            Byte[] TempPublicConstant28 = new Byte[4];
            Byte[] TempPublicConstant29 = new Byte[4];
            Byte[] TempPublicConstant30 = new Byte[4];
            Byte[] TempPublicConstant31 = new Byte[4];
            Byte[] TempPublicConstant32 = new Byte[4];
            uint[] SubPublicConstantUInt1 = new uint[2];
            uint[] SubPublicConstantUInt2 = new uint[2];
            uint[] SubPublicConstantUInt3 = new uint[2];
            uint[] SubPublicConstantUInt4 = new uint[2];
            uint[] SubPublicConstantUInt5 = new uint[2];
            uint[] SubPublicConstantUInt6 = new uint[2];
            uint[] SubPublicConstantUInt7 = new uint[2];
            uint[] SubPublicConstantUInt8 = new uint[2];
            uint[] SubPublicConstantUInt9 = new uint[2];
            uint[] SubPublicConstantUInt10 = new uint[2];
            uint[] SubPublicConstantUInt11 = new uint[2];
            uint[] SubPublicConstantUInt12 = new uint[2];
            uint[] SubPublicConstantUInt13 = new uint[2];
            uint[] SubPublicConstantUInt14 = new uint[2];
            uint[] SubPublicConstantUInt15 = new uint[2];
            uint[] SubPublicConstantUInt16 = new uint[2];
            Byte[] SubKey1 = new Byte[] { };
            Byte[] SubKey2 = new Byte[] { };
            Byte[] SubKey3 = new Byte[] { };
            Byte[] SubKey4 = new Byte[] { };
            Byte[] ConcatedSubKey = new Byte[] { };
            Byte[] DerivedKey = new Byte[] { };
            int Loop = 0;
            Array.Copy(Key, 0, TempKey1, 0, 4);
            Array.Copy(Key, 4, TempKey2, 0, 4);
            Array.Copy(Key, 8, TempKey3, 0, 4);
            Array.Copy(Key, 12, TempKey4, 0, 4);
            Array.Copy(Key, 16, TempKey5, 0, 4);
            Array.Copy(Key, 20, TempKey6, 0, 4);
            Array.Copy(Key, 24, TempKey7, 0, 4);
            Array.Copy(Key, 28, TempKey8, 0, 4);
            SubKeyUInt1[0] = BitConverter.ToUInt32(TempKey1);
            SubKeyUInt1[1] = BitConverter.ToUInt32(TempKey2);
            SubKeyUInt2[0] = BitConverter.ToUInt32(TempKey3);
            SubKeyUInt2[1] = BitConverter.ToUInt32(TempKey4);
            SubKeyUInt3[0] = BitConverter.ToUInt32(TempKey5);
            SubKeyUInt3[1] = BitConverter.ToUInt32(TempKey6);
            SubKeyUInt4[0] = BitConverter.ToUInt32(TempKey7);
            SubKeyUInt4[1] = BitConverter.ToUInt32(TempKey8);
            Array.Copy(SecretMaterial, 0, SubSecretMaterial1, 0, 32);
            Array.Copy(SecretMaterial, 32, SubSecretMaterial2, 0, 32);
            Array.Copy(SecretMaterial, 64, SubSecretMaterial3, 0, 32);
            Array.Copy(SecretMaterial, 96, SubSecretMaterial4, 0, 32);
            Array.Copy(SubSecretMaterial1, 0, TempSubSecretMaterial1, 0, 4);
            Array.Copy(SubSecretMaterial1, 4, TempSubSecretMaterial2, 0, 4);
            Array.Copy(SubSecretMaterial1, 8, TempSubSecretMaterial3, 0, 4);
            Array.Copy(SubSecretMaterial1, 12, TempSubSecretMaterial4, 0, 4);
            Array.Copy(SubSecretMaterial1, 16, TempSubSecretMaterial5, 0, 4);
            Array.Copy(SubSecretMaterial1, 20, TempSubSecretMaterial6, 0, 4);
            Array.Copy(SubSecretMaterial1, 24, TempSubSecretMaterial7, 0, 4);
            Array.Copy(SubSecretMaterial1, 28, TempSubSecretMaterial8, 0, 4);
            Array.Copy(SubSecretMaterial2, 0, TempSubSecretMaterial9, 0, 4);
            Array.Copy(SubSecretMaterial2, 4, TempSubSecretMaterial10, 0, 4);
            Array.Copy(SubSecretMaterial2, 8, TempSubSecretMaterial11, 0, 4);
            Array.Copy(SubSecretMaterial2, 12, TempSubSecretMaterial12, 0, 4);
            Array.Copy(SubSecretMaterial2, 16, TempSubSecretMaterial13, 0, 4);
            Array.Copy(SubSecretMaterial2, 20, TempSubSecretMaterial14, 0, 4);
            Array.Copy(SubSecretMaterial2, 24, TempSubSecretMaterial15, 0, 4);
            Array.Copy(SubSecretMaterial2, 28, TempSubSecretMaterial16, 0, 4);
            Array.Copy(SubSecretMaterial3, 0, TempSubSecretMaterial17, 0, 4);
            Array.Copy(SubSecretMaterial3, 4, TempSubSecretMaterial18, 0, 4);
            Array.Copy(SubSecretMaterial3, 8, TempSubSecretMaterial19, 0, 4);
            Array.Copy(SubSecretMaterial3, 12, TempSubSecretMaterial20, 0, 4);
            Array.Copy(SubSecretMaterial3, 16, TempSubSecretMaterial21, 0, 4);
            Array.Copy(SubSecretMaterial3, 20, TempSubSecretMaterial22, 0, 4);
            Array.Copy(SubSecretMaterial3, 24, TempSubSecretMaterial23, 0, 4);
            Array.Copy(SubSecretMaterial3, 28, TempSubSecretMaterial24, 0, 4);
            Array.Copy(SubSecretMaterial4, 0, TempSubSecretMaterial25, 0, 4);
            Array.Copy(SubSecretMaterial4, 4, TempSubSecretMaterial26, 0, 4);
            Array.Copy(SubSecretMaterial4, 8, TempSubSecretMaterial27, 0, 4);
            Array.Copy(SubSecretMaterial4, 12, TempSubSecretMaterial28, 0, 4);
            Array.Copy(SubSecretMaterial4, 16, TempSubSecretMaterial29, 0, 4);
            Array.Copy(SubSecretMaterial4, 20, TempSubSecretMaterial30, 0, 4);
            Array.Copy(SubSecretMaterial4, 24, TempSubSecretMaterial31, 0, 4);
            Array.Copy(SubSecretMaterial4, 28, TempSubSecretMaterial32, 0, 4);
            Array.Copy(PublicConstant1, 0, TempPublicConstant1, 0, 4);
            Array.Copy(PublicConstant1, 4, TempPublicConstant2, 0, 4);
            Array.Copy(PublicConstant1, 8, TempPublicConstant3, 0, 4);
            Array.Copy(PublicConstant1, 12, TempPublicConstant4, 0, 4);
            Array.Copy(PublicConstant1, 16, TempPublicConstant5, 0, 4);
            Array.Copy(PublicConstant1, 20, TempPublicConstant6, 0, 4);
            Array.Copy(PublicConstant1, 24, TempPublicConstant7, 0, 4);
            Array.Copy(PublicConstant1, 28, TempPublicConstant8, 0, 4);
            Array.Copy(PublicConstant2, 0, TempPublicConstant9, 0, 4);
            Array.Copy(PublicConstant2, 4, TempPublicConstant10, 0, 4);
            Array.Copy(PublicConstant2, 8, TempPublicConstant11, 0, 4);
            Array.Copy(PublicConstant2, 12, TempPublicConstant12, 0, 4);
            Array.Copy(PublicConstant2, 16, TempPublicConstant13, 0, 4);
            Array.Copy(PublicConstant2, 20, TempPublicConstant14, 0, 4);
            Array.Copy(PublicConstant2, 24, TempPublicConstant15, 0, 4);
            Array.Copy(PublicConstant2, 28, TempPublicConstant16, 0, 4);
            Array.Copy(PublicConstant3, 0, TempPublicConstant17, 0, 4);
            Array.Copy(PublicConstant3, 4, TempPublicConstant18, 0, 4);
            Array.Copy(PublicConstant3, 8, TempPublicConstant19, 0, 4);
            Array.Copy(PublicConstant3, 12, TempPublicConstant20, 0, 4);
            Array.Copy(PublicConstant3, 16, TempPublicConstant21, 0, 4);
            Array.Copy(PublicConstant3, 20, TempPublicConstant22, 0, 4);
            Array.Copy(PublicConstant3, 24, TempPublicConstant23, 0, 4);
            Array.Copy(PublicConstant3, 28, TempPublicConstant24, 0, 4);
            Array.Copy(PublicConstant4, 0, TempPublicConstant25, 0, 4);
            Array.Copy(PublicConstant4, 4, TempPublicConstant26, 0, 4);
            Array.Copy(PublicConstant4, 8, TempPublicConstant27, 0, 4);
            Array.Copy(PublicConstant4, 12, TempPublicConstant28, 0, 4);
            Array.Copy(PublicConstant4, 16, TempPublicConstant29, 0, 4);
            Array.Copy(SubSecretMaterial4, 20, TempPublicConstant30, 0, 4);
            Array.Copy(SubSecretMaterial4, 24, TempPublicConstant31, 0, 4);
            Array.Copy(SubSecretMaterial4, 28, TempPublicConstant32, 0, 4);
            SubSecretMaterialUInt1[0] = BitConverter.ToUInt32(TempSubSecretMaterial1);
            SubSecretMaterialUInt1[1] = BitConverter.ToUInt32(TempSubSecretMaterial2);
            SubSecretMaterialUInt2[0] = BitConverter.ToUInt32(TempSubSecretMaterial3);
            SubSecretMaterialUInt2[1] = BitConverter.ToUInt32(TempSubSecretMaterial4);
            SubSecretMaterialUInt3[0] = BitConverter.ToUInt32(TempSubSecretMaterial5);
            SubSecretMaterialUInt3[1] = BitConverter.ToUInt32(TempSubSecretMaterial6);
            SubSecretMaterialUInt4[0] = BitConverter.ToUInt32(TempSubSecretMaterial7);
            SubSecretMaterialUInt4[1] = BitConverter.ToUInt32(TempSubSecretMaterial8);
            SubSecretMaterialUInt5[0] = BitConverter.ToUInt32(TempSubSecretMaterial9);
            SubSecretMaterialUInt5[1] = BitConverter.ToUInt32(TempSubSecretMaterial10);
            SubSecretMaterialUInt6[0] = BitConverter.ToUInt32(TempSubSecretMaterial11);
            SubSecretMaterialUInt6[1] = BitConverter.ToUInt32(TempSubSecretMaterial12);
            SubSecretMaterialUInt7[0] = BitConverter.ToUInt32(TempSubSecretMaterial13);
            SubSecretMaterialUInt7[1] = BitConverter.ToUInt32(TempSubSecretMaterial14);
            SubSecretMaterialUInt8[0] = BitConverter.ToUInt32(TempSubSecretMaterial15);
            SubSecretMaterialUInt8[1] = BitConverter.ToUInt32(TempSubSecretMaterial16);
            SubSecretMaterialUInt9[0] = BitConverter.ToUInt32(TempSubSecretMaterial17);
            SubSecretMaterialUInt9[1] = BitConverter.ToUInt32(TempSubSecretMaterial18);
            SubSecretMaterialUInt10[0] = BitConverter.ToUInt32(TempSubSecretMaterial19);
            SubSecretMaterialUInt10[1] = BitConverter.ToUInt32(TempSubSecretMaterial20);
            SubSecretMaterialUInt11[0] = BitConverter.ToUInt32(TempSubSecretMaterial21);
            SubSecretMaterialUInt11[1] = BitConverter.ToUInt32(TempSubSecretMaterial22);
            SubSecretMaterialUInt12[0] = BitConverter.ToUInt32(TempSubSecretMaterial23);
            SubSecretMaterialUInt12[1] = BitConverter.ToUInt32(TempSubSecretMaterial24);
            SubSecretMaterialUInt13[0] = BitConverter.ToUInt32(TempSubSecretMaterial25);
            SubSecretMaterialUInt13[1] = BitConverter.ToUInt32(TempSubSecretMaterial26);
            SubSecretMaterialUInt14[0] = BitConverter.ToUInt32(TempSubSecretMaterial27);
            SubSecretMaterialUInt14[1] = BitConverter.ToUInt32(TempSubSecretMaterial28);
            SubSecretMaterialUInt15[0] = BitConverter.ToUInt32(TempSubSecretMaterial29);
            SubSecretMaterialUInt15[1] = BitConverter.ToUInt32(TempSubSecretMaterial30);
            SubSecretMaterialUInt16[0] = BitConverter.ToUInt32(TempSubSecretMaterial31);
            SubSecretMaterialUInt16[1] = BitConverter.ToUInt32(TempSubSecretMaterial32);
            SubPublicConstantUInt1[0] = BitConverter.ToUInt32(TempPublicConstant1);
            SubPublicConstantUInt1[1] = BitConverter.ToUInt32(TempPublicConstant2);
            SubPublicConstantUInt2[0] = BitConverter.ToUInt32(TempPublicConstant3);
            SubPublicConstantUInt2[1] = BitConverter.ToUInt32(TempPublicConstant4);
            SubPublicConstantUInt3[0] = BitConverter.ToUInt32(TempPublicConstant5);
            SubPublicConstantUInt3[1] = BitConverter.ToUInt32(TempPublicConstant6);
            SubPublicConstantUInt4[0] = BitConverter.ToUInt32(TempPublicConstant7);
            SubPublicConstantUInt4[1] = BitConverter.ToUInt32(TempPublicConstant8);
            SubPublicConstantUInt5[0] = BitConverter.ToUInt32(TempPublicConstant9);
            SubPublicConstantUInt5[1] = BitConverter.ToUInt32(TempPublicConstant10);
            SubPublicConstantUInt6[0] = BitConverter.ToUInt32(TempPublicConstant11);
            SubPublicConstantUInt6[1] = BitConverter.ToUInt32(TempPublicConstant12);
            SubPublicConstantUInt7[0] = BitConverter.ToUInt32(TempPublicConstant13);
            SubPublicConstantUInt7[1] = BitConverter.ToUInt32(TempPublicConstant14);
            SubPublicConstantUInt8[0] = BitConverter.ToUInt32(TempPublicConstant15);
            SubPublicConstantUInt8[1] = BitConverter.ToUInt32(TempPublicConstant16);
            SubPublicConstantUInt9[0] = BitConverter.ToUInt32(TempPublicConstant17);
            SubPublicConstantUInt9[1] = BitConverter.ToUInt32(TempPublicConstant18);
            SubPublicConstantUInt10[0] = BitConverter.ToUInt32(TempPublicConstant19);
            SubPublicConstantUInt10[1] = BitConverter.ToUInt32(TempPublicConstant20);
            SubPublicConstantUInt11[0] = BitConverter.ToUInt32(TempPublicConstant21);
            SubPublicConstantUInt11[1] = BitConverter.ToUInt32(TempPublicConstant22);
            SubPublicConstantUInt12[0] = BitConverter.ToUInt32(TempPublicConstant23);
            SubPublicConstantUInt12[1] = BitConverter.ToUInt32(TempPublicConstant24);
            SubPublicConstantUInt13[0] = BitConverter.ToUInt32(TempPublicConstant25);
            SubPublicConstantUInt13[1] = BitConverter.ToUInt32(TempPublicConstant26);
            SubPublicConstantUInt14[0] = BitConverter.ToUInt32(TempPublicConstant27);
            SubPublicConstantUInt14[1] = BitConverter.ToUInt32(TempPublicConstant28);
            SubPublicConstantUInt15[0] = BitConverter.ToUInt32(TempPublicConstant29);
            SubPublicConstantUInt15[1] = BitConverter.ToUInt32(TempPublicConstant30);
            SubPublicConstantUInt16[0] = BitConverter.ToUInt32(TempPublicConstant31);
            SubPublicConstantUInt16[1] = BitConverter.ToUInt32(TempPublicConstant32);
            SodiumSecureMemory.SecureClearBytes(TempKey1);
            SodiumSecureMemory.SecureClearBytes(TempKey2);
            SodiumSecureMemory.SecureClearBytes(TempKey3);
            SodiumSecureMemory.SecureClearBytes(TempKey4);
            SodiumSecureMemory.SecureClearBytes(TempKey5);
            SodiumSecureMemory.SecureClearBytes(TempKey6);
            SodiumSecureMemory.SecureClearBytes(TempKey7);
            SodiumSecureMemory.SecureClearBytes(TempKey8);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial1);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial2);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial3);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial4);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial5);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial6);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial7);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial8);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial9);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial10);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial11);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial12);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial13);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial14);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial15);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial16);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial17);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial18);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial19);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial20);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial21);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial22);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial23);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial24);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial25);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial26);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial27);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial28);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial29);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial30);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial31);
            SodiumSecureMemory.SecureClearBytes(TempSubSecretMaterial32);
            while (Loop < 2) 
            {
                SubKeyUInt1[Loop] = SubKeyUInt1[Loop] ^ SubPublicConstantUInt1[Loop] ^ SubPublicConstantUInt5[Loop] ^ SubPublicConstantUInt9[Loop] ^ SubPublicConstantUInt13[Loop];
                SubKeyUInt2[Loop] = SubKeyUInt2[Loop] ^ SubPublicConstantUInt2[Loop] ^ SubPublicConstantUInt6[Loop] ^ SubPublicConstantUInt10[Loop] ^ SubPublicConstantUInt14[Loop];
                SubKeyUInt3[Loop] = SubKeyUInt2[Loop] ^ SubPublicConstantUInt3[Loop] ^ SubPublicConstantUInt7[Loop] ^ SubPublicConstantUInt11[Loop] ^ SubPublicConstantUInt15[Loop];
                SubKeyUInt4[Loop] = SubKeyUInt2[Loop] ^ SubPublicConstantUInt4[Loop] ^ SubPublicConstantUInt8[Loop] ^ SubPublicConstantUInt12[Loop] ^ SubPublicConstantUInt16[Loop];
                Loop += 1;
            }            
            Loop = 0;
            while (Loop < 2) 
            {
                SubKeyUInt1[Loop] = SubKeyUInt1[Loop] ^ SubSecretMaterialUInt1[Loop] ^ SubSecretMaterialUInt5[Loop] ^ SubSecretMaterialUInt9[Loop] ^ SubSecretMaterialUInt13[Loop];
                SubKeyUInt2[Loop] = SubKeyUInt2[Loop] ^ SubSecretMaterialUInt2[Loop] ^ SubSecretMaterialUInt6[Loop] ^ SubSecretMaterialUInt10[Loop] ^ SubSecretMaterialUInt14[Loop];
                SubKeyUInt3[Loop] = SubKeyUInt2[Loop] ^ SubSecretMaterialUInt3[Loop] ^ SubSecretMaterialUInt7[Loop] ^ SubSecretMaterialUInt11[Loop] ^ SubSecretMaterialUInt15[Loop];
                SubKeyUInt4[Loop] = SubKeyUInt2[Loop] ^ SubSecretMaterialUInt4[Loop] ^ SubSecretMaterialUInt8[Loop] ^ SubSecretMaterialUInt12[Loop] ^ SubSecretMaterialUInt16[Loop];
                Loop += 1;
            }            
            Loop = 0;
            while (Loop < 2)
            {
                SubKey1 = SubKey1.Concat(ConvertUIntToByteArray(SubKeyUInt1[Loop])).ToArray();
                SubKey2 = SubKey2.Concat(ConvertUIntToByteArray(SubKeyUInt2[Loop])).ToArray();
                SubKey3 = SubKey3.Concat(ConvertUIntToByteArray(SubKeyUInt3[Loop])).ToArray();
                SubKey4 = SubKey4.Concat(ConvertUIntToByteArray(SubKeyUInt4[Loop])).ToArray();
                Loop += 1;
            }
            ConcatedSubKey = SubKey1.Concat(SubKey2).Concat(SubKey3).Concat(SubKey4).ToArray();
            DerivedKey = SodiumKDF.KDFFunction(32, 1, "KDFForFC", ConcatedSubKey, true);

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt1, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt1.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt2, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt2.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt3, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt3.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt4, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt4.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt1, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt1.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt2, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt2.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt3, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt3.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt4, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt4.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt5, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt5.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt6, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt6.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt7, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt7.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt8, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt8.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt9, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt9.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt10, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt10.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt11, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt11.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt12, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt12.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt13, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt13.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt14, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt14.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt15, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt15.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubSecretMaterialUInt16, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubSecretMaterialUInt16.Length * 4);
            MyGeneralGCHandle.Free();
            SodiumSecureMemory.SecureClearBytes(SubKey1);
            SodiumSecureMemory.SecureClearBytes(SubKey2);
            SodiumSecureMemory.SecureClearBytes(SubKey3);
            SodiumSecureMemory.SecureClearBytes(SubKey4);
            return DerivedKey;
        }


        private static Byte[] ConvertUIntToByteArray(uint Value) 
        {
            return BitConverter.GetBytes(Value);
        }

        private static Byte[] FRXOR(Byte[] Source1, Byte[] Source2)
        {
            if (Source1 == null)
            {
                throw new ArgumentException("Error: Source1 byte array can't be null");
            }
            if (Source2 == null)
            {
                throw new ArgumentException("Error: Source2 byte array can't be null");
            }
            if (Source1.Length != Source2.Length)
            {
                throw new ArgumentException("Error: Source1 and source2 byte array length must be the same");
            }
            if (Source1.Length % 4 != 0)
            {
                throw new ArgumentException("Error: Source1 and source2 byte array length must be divisible by 4");
            }
            int ArrayCount = Source1.Length / 4;
            uint[] Source1uint = new uint[ArrayCount];
            uint[] Source2uint = new uint[ArrayCount];
            uint[] xoreduint = new uint[ArrayCount];
            int Loop = 0;
            Byte[] XOREDByte = new Byte[] { };
            GCHandle MyGeneralGCHandle;
            Byte[] TempArray1 = new Byte[4];
            Byte[] TempArray2 = new Byte[4];
            while (Loop < ArrayCount)
            {
                TempArray1 = new Byte[4];
                TempArray2 = new Byte[4];
                Array.Copy(Source1, (Loop * 4), TempArray1, 0, 4);
                Array.Copy(Source2, (Loop * 4), TempArray2, 0, 4);
                Source1uint[Loop] = BitConverter.ToUInt32(TempArray1);
                Source2uint[Loop] = BitConverter.ToUInt32(TempArray2);
                SodiumSecureMemory.SecureClearBytes(TempArray1);
                SodiumSecureMemory.SecureClearBytes(TempArray2);
                Loop += 1;
            }
            Loop = 0;
            while (Loop < Source1uint.Length)
            {
                xoreduint[Loop] = Source1uint[Loop] ^ Source2uint[Loop];
                Loop += 1;
            }
            Loop = 0;
            while (Loop < ArrayCount)
            {
                XOREDByte = XOREDByte.Concat(BitConverter.GetBytes(xoreduint[Loop])).ToArray();
                Loop += 1;
            }
            MyGeneralGCHandle = GCHandle.Alloc(Source1uint, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source1uint.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(Source2uint, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source2uint.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(xoreduint, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), xoreduint.Length * 4);
            MyGeneralGCHandle.Free();
            return XOREDByte;
        }
    }
}
