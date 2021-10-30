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
            Byte[] TempSubKey = new Byte[] { };
            Byte[] DerivedSubKey = new Byte[] { };
            Byte[] SubKey = new Byte[] { };
            Byte[] RoundKey = new Byte[] { };
            Byte[] HMAC = new Byte[] { };
            Byte[] SubHMAC1 = new Byte[16];
            Byte[] SubHMAC2 = new Byte[16];
            Byte[] Salt = new Byte[SodiumPasswordHashArgon2.GetSaltBytesLength()];
            Byte[] ActualCipherText = new Byte[] { };
            int Count = 16;
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
                    SubKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, Key, Salt,SodiumPasswordHashArgon2.Strength.INTERACTIVE);
                }
                else 
                {
                    PreviousSubKey = SubKey;
                    TempSubKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, Key, Salt, SodiumPasswordHashArgon2.Strength.INTERACTIVE);
                    DerivedSubKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, PreviousSubKey, Salt, SodiumPasswordHashArgon2.Strength.INTERACTIVE);
                    SubKey = XORHelper.XOR(DerivedSubKey, TempSubKey);
                    SodiumSecureMemory.SecureClearBytes(DerivedSubKey);
                    SodiumSecureMemory.SecureClearBytes(TempSubKey);
                    SodiumSecureMemory.SecureClearBytes(PreviousSubKey);
                }
                RoundKey = GenerateRoundKey(SubKey);
                HMAC = GenerateHMACTextAsKey(RightMessage, RoundKey);
                Array.Copy(HMAC, 0, SubHMAC1, 0, 16);
                Array.Copy(HMAC, 16, SubHMAC2, 0, 16);
                CipherText = XORHelper.XOR(LeftMessage, SubHMAC1);
                CipherText = XORHelper.XOR(CipherText, SubHMAC2);
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
            Byte[] TempSubKey = new Byte[] { };
            Byte[] DerivedSubKey = new Byte[] { };
            Byte[] SubKey = new Byte[] { };
            Byte[] RoundKey = new Byte[] { };
            Byte[] HMAC = new Byte[] { };
            Byte[] SubHMAC1 = new Byte[16];
            Byte[] SubHMAC2 = new Byte[16];
            Byte[] Salt = new Byte[SodiumPasswordHashArgon2.GetSaltBytesLength()];
            Byte[] ActualBuff = new Byte[] { };
            Byte Count = 16;
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
                    SubKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, Key, Salt, SodiumPasswordHashArgon2.Strength.INTERACTIVE);
                }
                else
                {
                    PreviousSubKey = SubKey;
                    TempSubKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, Key, Salt, SodiumPasswordHashArgon2.Strength.INTERACTIVE);
                    DerivedSubKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, PreviousSubKey, Salt, SodiumPasswordHashArgon2.Strength.INTERACTIVE);
                    SubKey = XORHelper.XOR(DerivedSubKey, TempSubKey);
                    SodiumSecureMemory.SecureClearBytes(DerivedSubKey);
                    SodiumSecureMemory.SecureClearBytes(TempSubKey);
                    SodiumSecureMemory.SecureClearBytes(PreviousSubKey);
                }
                RoundKey = GenerateRoundKey(SubKey);
                HMAC = GenerateHMACTextAsKey(RightMessage, RoundKey);
                Array.Copy(HMAC, 0, SubHMAC1, 0, 16);
                Array.Copy(HMAC, 16, SubHMAC2, 0, 16);
                Buff = XORHelper.XOR(LeftMessage, SubHMAC1);
                Buff = XORHelper.XOR(Buff, SubHMAC2);
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
            Byte[] SubHMAC1 = new Byte[32];
            Byte[] SubHMAC2 = new Byte[32];
            SubKey = SodiumKDF.KDFFunction(32, 1, "KDFFHMAC", Key);
            RoundKey = GenerateRoundKey(SubKey);
            HMAC = SHAKEDigest.ComputeHMAC(Message, RoundKey);
            Array.Copy(HMAC,0,SubHMAC1,0,32);
            Array.Copy(HMAC, 32, SubHMAC2, 0, 32);
            SodiumSecureMemory.SecureClearBytes(HMAC);
            HMAC = XORHelper.XOR(SubHMAC1, SubHMAC2);
            HMAC = XORHelper.XOR(HMAC, RoundKey);
            HMAC = XORHelper.XOR(HMAC, SubKey);
            SodiumSecureMemory.SecureClearBytes(SubHMAC1);
            SodiumSecureMemory.SecureClearBytes(SubHMAC2);
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
            uint[] SubKeyUInt1 = new uint[4];
            uint[] SubKeyUInt2 = new uint[4];
            uint[] SubKeyUInt3 = new uint[4];
            uint[] SubKeyUInt4 = new uint[4];
            uint[] SubKeyUInt5 = new uint[4];
            uint[] SubKeyUInt6 = new uint[4];
            uint[] SubKeyUInt7 = new uint[4];
            uint[] SubKeyUInt8 = new uint[4];
            Byte[] SubKey1 = new Byte[] { };
            Byte[] SubKey2 = new Byte[] { };
            Byte[] SubKey3 = new Byte[] { };
            Byte[] SubKey4 = new Byte[] { };
            Byte[] SubKey5 = new Byte[] { };
            Byte[] SubKey6 = new Byte[] { };
            Byte[] SubKey7 = new Byte[] { };
            Byte[] SubKey8 = new Byte[] { };
            Byte[] ConcatedSubKey = new Byte[] { };
            Byte[] MasterKey = new Byte[] { };
            int Loop = 0;
            int SubKeyUIntLoop = 0;
            Array.Copy(Key, 0, SubKeyUInt1, 0, 4);
            Array.Copy(Key, 4, SubKeyUInt2, 0, 4);
            Array.Copy(Key, 8, SubKeyUInt3, 0, 4);
            Array.Copy(Key, 12, SubKeyUInt4, 0, 4);
            Array.Copy(Key, 16, SubKeyUInt5, 0, 4);
            Array.Copy(Key, 20, SubKeyUInt6, 0, 4);
            Array.Copy(Key, 24, SubKeyUInt7, 0, 4);
            Array.Copy(Key, 28, SubKeyUInt8, 0, 4);
            while (Loop < 16)
            {
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] ^= SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] ^= SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] ^= SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] >> 4;
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] >> 4;
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] >> 4;
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] >> 4;
                SubKeyUInt5[SubKeyUIntLoop] = SubKeyUInt5[SubKeyUIntLoop] >> 4;
                SubKeyUInt6[SubKeyUIntLoop] = SubKeyUInt6[SubKeyUIntLoop] >> 4;
                SubKeyUInt7[SubKeyUIntLoop] = SubKeyUInt7[SubKeyUIntLoop] >> 4;
                SubKeyUInt8[SubKeyUIntLoop] = SubKeyUInt8[SubKeyUIntLoop] >> 4;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] ^= SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] ^= SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] ^= SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] << 4;
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] << 4;
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] << 4;
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] << 4;
                SubKeyUInt5[SubKeyUIntLoop] = SubKeyUInt5[SubKeyUIntLoop] << 4;
                SubKeyUInt6[SubKeyUIntLoop] = SubKeyUInt6[SubKeyUIntLoop] << 4;
                SubKeyUInt7[SubKeyUIntLoop] = SubKeyUInt7[SubKeyUIntLoop] << 4;
                SubKeyUInt8[SubKeyUIntLoop] = SubKeyUInt8[SubKeyUIntLoop] << 4;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] ^= SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] ^= SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] ^= SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] = SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] = SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] = SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] >> 4;
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] <<= 4;
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                if (SubKeyUIntLoop == 3)
                {
                    SubKeyUIntLoop = 0;
                }
                SubKeyUIntLoop += 1;
                Loop += 1;
            }
            Loop = 0;
            SubKeyUIntLoop = 0;
            while (Loop < 16)
            {
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] >> 4;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt1[SubKeyUIntLoop] = SubKeyUInt1[SubKeyUIntLoop] << 6;
                SubKeyUInt1[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] >> 4;
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt2[SubKeyUIntLoop] = SubKeyUInt2[SubKeyUIntLoop] << 6;
                SubKeyUInt2[SubKeyUIntLoop] ^= SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt4[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] >> 4;
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt3[SubKeyUIntLoop] = SubKeyUInt3[SubKeyUIntLoop] << 6;
                SubKeyUInt3[SubKeyUIntLoop] ^= SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt5[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] >> 4;
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt4[SubKeyUIntLoop] = SubKeyUInt4[SubKeyUIntLoop] << 6;
                SubKeyUInt4[SubKeyUIntLoop] ^= SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] ^= SubKeyUInt6[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] = SubKeyUInt5[SubKeyUIntLoop] >> 4;
                SubKeyUInt5[SubKeyUIntLoop] ^= SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt5[SubKeyUIntLoop] = SubKeyUInt5[SubKeyUIntLoop] << 6;
                SubKeyUInt5[SubKeyUIntLoop] ^= SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] ^= SubKeyUInt7[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] = SubKeyUInt6[SubKeyUIntLoop] >> 4;
                SubKeyUInt6[SubKeyUIntLoop] ^= SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt6[SubKeyUIntLoop] = SubKeyUInt6[SubKeyUIntLoop] << 6;
                SubKeyUInt6[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] ^= SubKeyUInt8[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] = SubKeyUInt7[SubKeyUIntLoop] >> 4;
                SubKeyUInt7[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt7[SubKeyUIntLoop] = SubKeyUInt7[SubKeyUIntLoop] << 6;
                SubKeyUInt7[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt1[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] = SubKeyUInt8[SubKeyUIntLoop] >> 4;
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt2[SubKeyUIntLoop];
                SubKeyUInt8[SubKeyUIntLoop] = SubKeyUInt8[SubKeyUIntLoop] << 6;
                SubKeyUInt8[SubKeyUIntLoop] ^= SubKeyUInt3[SubKeyUIntLoop];
                if (SubKeyUIntLoop == 3)
                {
                    SubKeyUIntLoop = 0;
                }
                SubKeyUIntLoop += 1;
                Loop += 1;
            }
            Loop = 0;
            while (Loop < 4)
            {
                SubKey1 = SubKey1.Concat(ConvertUIntToByteArray(SubKeyUInt1[Loop])).ToArray();
                SubKey2 = SubKey2.Concat(ConvertUIntToByteArray(SubKeyUInt2[Loop])).ToArray();
                SubKey3 = SubKey3.Concat(ConvertUIntToByteArray(SubKeyUInt3[Loop])).ToArray();
                SubKey4 = SubKey4.Concat(ConvertUIntToByteArray(SubKeyUInt4[Loop])).ToArray();
                SubKey5 = SubKey5.Concat(ConvertUIntToByteArray(SubKeyUInt5[Loop])).ToArray();
                SubKey6 = SubKey6.Concat(ConvertUIntToByteArray(SubKeyUInt6[Loop])).ToArray();
                SubKey7 = SubKey7.Concat(ConvertUIntToByteArray(SubKeyUInt7[Loop])).ToArray();
                SubKey8 = SubKey8.Concat(ConvertUIntToByteArray(SubKeyUInt8[Loop])).ToArray();
                Loop += 1;
            }
            ConcatedSubKey = SubKey1.Concat(SubKey2).Concat(SubKey3).Concat(SubKey4).
                Concat(SubKey5).Concat(SubKey6).Concat(SubKey7).Concat(SubKey8).ToArray();
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
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt5, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt5.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt6, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt6.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt7, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt7.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(SubKeyUInt8, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKeyUInt8.Length * 4);
            MyGeneralGCHandle.Free();

            SodiumSecureMemory.SecureClearBytes(SubKey1);
            SodiumSecureMemory.SecureClearBytes(SubKey2);
            SodiumSecureMemory.SecureClearBytes(SubKey3);
            SodiumSecureMemory.SecureClearBytes(SubKey4);
            SodiumSecureMemory.SecureClearBytes(SubKey5);
            SodiumSecureMemory.SecureClearBytes(SubKey6);
            SodiumSecureMemory.SecureClearBytes(SubKey7);
            SodiumSecureMemory.SecureClearBytes(SubKey8);
            return MasterKey;
        }


        private static Byte[] ConvertUIntToByteArray(uint Value) 
        {
            return BitConverter.GetBytes(Value);
        }
    }
}
