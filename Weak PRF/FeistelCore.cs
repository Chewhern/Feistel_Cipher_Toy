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
        public static Byte[] Encrypt(Byte[] Message,Byte[] Key,Boolean ClearKey=false) 
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
            Byte[] HMAC = new Byte[] { };
            Byte[] SubHMAC1 = new Byte[16];
            Byte[] SubHMAC2 = new Byte[16];
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
                RoundKey = GenerateRoundKey(SubKey);
                HMAC = GenerateHMACTextAsKey(RightMessage, RoundKey);
                Array.Copy(HMAC, 0, SubHMAC1, 0, 16);
                Array.Copy(HMAC, 16, SubHMAC2, 0, 16);
                CipherText = FRXOR(LeftMessage, SubHMAC1);
                CipherText = FRXOR(CipherText, SubHMAC2);
                LeftMessage = RightMessage;
                RightMessage = CipherText;
                SodiumSecureMemory.SecureClearBytes(RoundKey);
                SodiumSecureMemory.SecureClearBytes(HMAC);
                SodiumSecureMemory.SecureClearBytes(SubHMAC1);
                SodiumSecureMemory.SecureClearBytes(SubHMAC2);
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

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
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
            Byte[] HMAC = new Byte[] { };
            Byte[] SubHMAC1 = new Byte[16];
            Byte[] SubHMAC2 = new Byte[16];
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
                RoundKey = GenerateRoundKey(SubKey);
                HMAC = GenerateHMACTextAsKey(RightMessage, RoundKey);
                Array.Copy(HMAC, 0, SubHMAC1, 0, 16);
                Array.Copy(HMAC, 16, SubHMAC2, 0, 16);
                Buff = FRXOR(LeftMessage, SubHMAC1);
                Buff = FRXOR(Buff, SubHMAC2);
                LeftMessage = RightMessage;
                RightMessage = Buff;
                SodiumSecureMemory.SecureClearBytes(RoundKey);
                SodiumSecureMemory.SecureClearBytes(HMAC);
                SodiumSecureMemory.SecureClearBytes(SubHMAC1);
                SodiumSecureMemory.SecureClearBytes(SubHMAC2);
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
            }
            return ActualBuff;
        }

        public static Byte[] GenerateHMACTextAsKey(Byte[] Message,Byte[] Key) 
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
            Byte[] SubKey = new Byte[] { };
            Byte[] RoundKey = new Byte[] { };
            Byte[] HMAC = new Byte[] { };
            Byte[] TempHMAC1 = new Byte[] { };
            Byte[] TempHMAC2 = new Byte[] { };
            Byte[] SubHMAC1 = new Byte[32];
            Byte[] SubHMAC2 = new Byte[32];
            SubKey = SodiumKDF.KDFFunction(32, 1, "KDFFHMAC", Key);
            RoundKey = GenerateRoundKey(SubKey);
            HMAC = SHAKEDigest.ComputeHMAC(Message, RoundKey);
            Array.Copy(HMAC,0,SubHMAC1,0,32);
            Array.Copy(HMAC, 32, SubHMAC2, 0, 32);
            SodiumSecureMemory.SecureClearBytes(HMAC);
            TempHMAC1 = FRXOR(SubHMAC1, SubHMAC2);
            TempHMAC2 = FRXOR(TempHMAC1, RoundKey);
            HMAC = FRXOR(TempHMAC2, SubKey);
            SodiumSecureMemory.SecureClearBytes(SubHMAC1);
            SodiumSecureMemory.SecureClearBytes(SubHMAC2);
            SodiumSecureMemory.SecureClearBytes(TempHMAC1);
            SodiumSecureMemory.SecureClearBytes(TempHMAC2);
            SodiumSecureMemory.SecureClearBytes(RoundKey);
            SodiumSecureMemory.SecureClearBytes(SubKey);
            return HMAC;
        }

        public static Byte[] GenerateRoundKey(Byte[] Key)
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
            Byte[] SubKey1 = new Byte[] { };
            Byte[] SubKey2 = new Byte[] { };
            Byte[] SubKey3 = new Byte[] { };
            Byte[] SubKey4 = new Byte[] { };
            Byte[] ConcatedSubKey = new Byte[] { };
            Byte[] MasterKey = new Byte[] { };
            int Loop = 0;
            int SubKeyUIntLoop = 0;
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
            SodiumSecureMemory.SecureClearBytes(TempKey1);
            SodiumSecureMemory.SecureClearBytes(TempKey2);
            SodiumSecureMemory.SecureClearBytes(TempKey3);
            SodiumSecureMemory.SecureClearBytes(TempKey4);
            SodiumSecureMemory.SecureClearBytes(TempKey5);
            SodiumSecureMemory.SecureClearBytes(TempKey6);
            SodiumSecureMemory.SecureClearBytes(TempKey7);
            SodiumSecureMemory.SecureClearBytes(TempKey8);
            while (Loop < 128)
            {
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] >> 2;
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] >> 2;
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] >> 2;
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] >> 2;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] << 4;
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] << 4;
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] << 4;
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] << 4;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop] >> 4;
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] <<= 2;
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                if (SubKeyUIntLoop == 1)
                {
                    SubKeyUIntLoop = 0;
                }
                SubKeyUIntLoop += 1;
                Loop += 1;
            }
            Loop = 0;
            SubKeyUIntLoop = 0;
            while (Loop < 128)
            {
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] >> 2;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] << 4;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] >> 2;
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] << 4;
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] >> 2;
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] << 4;
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] >> 2;
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] << 4;
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                if (SubKeyUIntLoop == 1)
                {
                    SubKeyUIntLoop = 0;
                }
                SubKeyUIntLoop += 1;
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
            MasterKey = SodiumKDF.KDFFunction(32, 1, "KDFForFC", ConcatedSubKey, true);

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

            SodiumSecureMemory.SecureClearBytes(SubKey1);
            SodiumSecureMemory.SecureClearBytes(SubKey2);
            SodiumSecureMemory.SecureClearBytes(SubKey3);
            SodiumSecureMemory.SecureClearBytes(SubKey4);
            return MasterKey;
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
