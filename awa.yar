//By 2096779623
import "pe"
import "hash"

rule Backdoor_CobaltStrike_exe_x86
{
    meta:
        description = "Backdoor.CobaltStrike.exe"
        author = "awa"
        date = "2021-08-04"
    strings:
        $ = {B9 AA 26 00 00 31 D2 C7 44 24 28 5C 00 00 00 C7 44 24 24 65 00 00 00 C7 44 24 20 70 00 00 00 C7 44 24 1C 69 00 00 00 C7 44 24 18 70 00 00 00 F7 F1 C7 44 24 14 5C 00 00 00 C7 44 24 10 2E 00 00 00 C7 44 24 0C 5C 00 00 00 C7 44 24 08 5C 00 00 00 C7 44 24 04 44 40 40 00 C7 04 24 F0 53 40 00 89 54 24}
    condition:
        any of them
}

rule Backdoor_CobaltStrike
{
    meta:
        description = "Backdoor.C2server"
        author = "awa"
        date = "2021-08-04"
    strings:
        $ = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii nocase
    condition:
        any of them
}

rule Backdoor_hta
{
    meta:
        description = "Backdoor.hta"
        author = "awa"
        date = "2021-08-04"
    strings:
        $a = "Function vshellcoder_func()" fullword ascii
    condition:
        any of them
}

rule Backdoor_hta_powershell
{
    meta:
        description = "Backdoor.hta.powershell"
        author = "awa"
        date = "2021-08-04"
    strings:
        $ = "powershell -nop -w hidden -encodedcommand"
    condition:
        any of them
}

rule Backdoor_hta_VB
{
    meta:
        description = "Backdoor.hta.VB"
        author = "awa"
        date = "2021-08-04"
    strings:
        $a = "<html><head><script language=\"vbscript\">" nocase fullword
        $b = "<\\script><\\head><\\html>"
        $c = "end if"
        $d = "self.close"
    condition:
        all of them
}

rule Backdoor_CobaltStrike_sct
{
    meta:
        description = "Backdoor.CobaltStrike.sct"
        author = "awa"
        date = "2021-08-04"
    strings:
        $Regkey= "RegPath = \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\" & objExcel.Version & \"\\Excel\\Security\\AccessVBOM\"" nocase
        $dim= "Dim objExcel, WshShell, RegPath, action, objWorkbook, xlmodule"
        $sct = "</registration>" nocase
    condition:
        all of them
}


rule msf_meterpreter
{
    meta:
        description = "msf.meterpreter"
        author = "awa"
        date = "2021-08-04"
    strings:
        $ = "%5I64d %4I64d %5.1f %6I64d %7I64d\n" fullword
    condition:
        all of them
}
rule msf_meterpreter_x64 {
    meta:
        description = "msf.meterpreter.x64"
        author = "awa"
        date = "2021-08-05"
    strings:
        $ = {45 78 69 74 50 72 6F 63 65 73 73 00 58 04 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C}
    condition:
        any of them
}
rule msf_meterpreter_powershell {
    meta:
        description = "msf.meterpreter.powershell"
    strings:
        $a = "[DllImport(\"kernel32.dll\")]"
        $b = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);"
        $c = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);"
        $d = "Add-Type -memberDefinition"
    condition:
        all of them
}


rule RemoteControl_Client {
    meta:
        description = "RemoteControl.Client"
        author = "awa"
        date = "2021-08-23"
    strings:
        $a = {52 65 6D 6F 74 65 43 6F 6E 74 72 6F 6C 2E 43 6C 69 65 6E 74}
        $b = "GetServerIP"
        $c = "SetServerIP"
        $d = {52 65 6D 6F 74 65 43 6F 6E 74 72 6F 6C 2E 50 72 6F 74 6F 63 61 6C 73}
    condition:
        all of them
}

rule Gen_Variant_MSIL_Cassiopeia_4 {
    meta:
        description = "Gen:Variant.MSIL.Cassiopeia.4"
        author = "awa"
        date = "2021-08-24"
    strings:
        $a = {86 8F EE 2E 55 2E 83 A3 0C 78 00 93 18 B0 0F 39}
        $b = "SoapHttpClientProtocol" fullword
    condition:
        all of them and filesize >= 128KB
}

rule Win32_MalwareX_gen {
    meta:
        description = "Win32:MalwareX-gen"
        author = "awa"
        date = "2021-08-24"
    strings:
        $a = {00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 57 00 43 00 48 00 6F 00 72 00 6B 00 66 00 6C 00 6F 00 77 00 41 00 70 00 70 00 6C 00 69 00 63 00 61 00 74 00 69 00 6F 00 6E 00 6D 00 46 00 43 00 6F 00 6D 00 70 00 6C 00 65 00 74 00 65 00 64 00 45 00 61 00 52 00 76 00 65 00 6E 00 74 00 41 00 72 00 67 00 73 00 00 00 3E 00 0F 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 38 00 30 00 2E 00 35 00 31 00 32 00 2E 00 35 00 32 00 34 00 2E 00 32 00 33 00 39 00 00 00 00 00 58 00 1C 00 01 00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6C 00 75 00 6D 00 6E 00 43 00 6C 00 69 00 63 00 6B 00 45 00 76 00 65 00 6E 00 74 00 48 00 61 00 6E 00 64 00 6C 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 80 00 2E 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 70 00 4D 00 54 00 48 00 79 00 70 00 65 00 46 00 6F 00 72 00 77 00 61 00 47 00 72 00 64 00 65 00 64 00 46 00 72 00 6F 00 6D 00 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 20 00 32 00 30 00 31 00 36 00 00 00 2A 00 01 00 01 00 4C 00 65 00 67 00 61 00 6C 00 54 00 72 00 61 00 64 00 65 00 6D 00 61 00 72 00 6B 00 73 00 00 00 00 00 00 00 00 00 60 00 1C 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6C 00 75 00 6D 00 6E 00 43 00 6C 00 69 00 63 00 6B 00 45 00 76 00 65 00 6E 00 74 00 48 00 61 00 6E 00 64 00 6C 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 5C 00 1E 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 48 00 74 00 74 00 70 00 52 00 65 00 71 00 68 00 50 00 68 00 75 00 65 00 73 00 74 00 43 00 61 00 63 00 68 00 73 00 79 00 65 00 50 00 6F 00 6C 00 69 00 63 00 79 00 48 00 53 00 00 00 42 00 0F 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 38 00 30 00 2E 00 35 00 31 00 32 00 2E 00 35 00 32 00 34 00 2E 00 32 00 33 00 39 00 00 00 00 00 48 00 10 00 01 00 41 00 73 00 73 00 65 00 6D 00 62 00 6C 00 79 00 20 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 39 00}
    condition:
        all of them and filesize >= 647KB
}

rule memz_bat {
   meta:
      description = "Geometry dash auto speedhack.bat"
      author = "awa"
      date = "2021-06-13"
      hash1 = "5e2cd213ff47b7657abd9167c38ffd8b53c13261fe22adddea92b5a2d9e320ad"
   strings:
      $s1 = "set v=\"%appdata%\\MEMZ.exe\"" fullword ascii
      $s2 = "echo f=new ActiveXObject(^\"Scripting.FileSystemObject^\");i=f.getFile(^\"x^\").openAsTextStream();>x.js" fullword ascii
      $s3 = "echo z=f.getAbsolutePathName(^\"z.zip^\");o.saveToFile(z);s=new ActiveXObject(^\"Shell.Application^\");>>x.js" fullword ascii
      $s4 = "echo x=new ActiveXObject(^\"MSXml2.DOMDocument^\").createElement(^\"Base64Data^\");x.dataType=^\"bin.base64^\";>>x.js" fullword ascii
      $s5 = "cscript x.js >NUL 2>NUL" fullword ascii
      $s6 = "start \"\" %v%" fullword ascii
      $s7 = "echo x.text=i.readAll();o=new ActiveXObject(^\"ADODB.Stream^\");o.type=1;o.open();o.write(x.nodeTypedValue);>>x.js" fullword ascii
      $s8 = "del %v% >NUL 2>NUL" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 50KB and
      2 of them
}

rule memz_exe {
   meta:
      description = "geometry dash auto speedhack.exe"
      author = "awa"
      date = "2021-06-13"
      hash1 = "a3d5715a81f2fbeb5f76c88c9c21eeee87142909716472f911ff6950c790c24d"
   strings:
      $s1 = "http://answers.microsoft.com/en-us/protect/forum/protect_other-protect_scanning/memz-malwarevirus-trojan-completely-destroying/2" ascii
      $s2 = "http://google.co.ck/search?q=virus.exe" fullword ascii
      $s3 = "http://answers.microsoft.com/en-us/protect/forum/protect_other-protect_scanning/memz-malwarevirus-trojan-completely-destroying/2" ascii
      $s4 = "http://motherboard.vice.com/read/watch-this-malware-turn-a-computer-into-a-digital-hellscape" fullword ascii
      $s5 = "http://google.co.ck/search?q=what+happens+if+you+delete+system32" fullword ascii
      $s6 = "If you are seeing this message without knowing what you just executed, simply press No and nothing will happen." fullword ascii
      $s7 = "DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?" fullword ascii
      $s8 = "The software you just executed is considered malware." fullword ascii
      $s9 = "STILL EXECUTE IT?" fullword ascii
      $s10 = "http://google.co.ck/search?q=minecraft+hax+download+no+virus" fullword ascii
      $s11 = "http://google.co.ck/search?q=how+to+download+memz" fullword ascii
      $s12 = "http://google.co.ck/search?q=virus+builder+legit+free+download" fullword ascii
      $s13 = "http://google.co.ck/search?q=bonzi+buddy+download+free" fullword ascii
      $s14 = "http://google.co.ck/search?q=batch+virus+download" fullword ascii
      $s15 = "http://google.co.ck/search?q=facebook+hacking+tool+free+download+no+virus+working+2016" fullword ascii
      $s16 = " - danooct1 2016" fullword ascii
      $x1 = "FUCKED BY THE MEMZ TROJAN" ascii
      $x2 = "//./PhysicalDrive0" ascii
      $x3 = "note.txt"
      $x4 = "BitBlt" fullword ascii
   condition:
      5 of them
}


rule Trojan_GenericKD_37375103 {
    meta:
        description = "Trojan.GenericKD.37375103"
        date = "2021-08-24"
        author = "awa"
        hash1 = "0ff4cbb5cd7a30da780fd16c5401ba6d2ae2c437bcb461351d38f494c964cd63"
    strings:
        $= {DA DA DA E7 EA EA EA FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E6 E6 E6 FF E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E6 E6 E6 FF E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E6 E6 E6 FF E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE E5 E5 E5 FE}
    condition:
        all of them and filesize >= 483KB
}

rule Trojan_GenericKD_37405164 {
    meta:
        description = "Trojan.GenericKD.37405164"
        date = "2021-08-24"
        author = "awa"
        hash1 = "1fc4a88f0220817b729357d09fdaef4fdc80e414d947ad35a8b4ddbd6bf28801"
    strings:
        $b = {51 75 65 72 79 50 65 72 66 6F 72 6D 61 6E 63 65 43 6F 75 6E 74 65 72}
        $a = {5C 64 64 5C 76 63 74 6F 6F 6C 73 5C 63 72 74 5F 62 6C 64 5C 73 65 6C 66 5F 78 38 36 5C 63 72 74 5C 73 72 63 5C 6D 62 63 74}
        $d = {43 72 74 44 62 67 52 65 70 6F 72 74 3A 20 53 74 72 69 6E 67 20 74 6F 6F 20 6C 6F 6E 67 20 6F 72 20 49 6E 76 61 6C 69 64 20 63 68 61 72 61 63 74 65 72 73 20 69 6E 20 53 74 72 69 6E}
        $e = {00 73 00 7A 00 4C 00 69 00 6E 00 65 00 4D 00 65 00 73 00 73 00 61 00 67 00 65}
        $c = {21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D}
    condition:
        all of them and filesize == 272KB
}

rule Trojan_GenericKD_37411650 {
    meta:
        description = "Trojan.GenericKD.37411650"
        date = "2021-08-24"
        author = "awa"
        hash1 = "2aafe51ed875d14265117e71337eaf72d2d22f8055ad43356062efbde0eb6f4a"
    strings:
        $a = "%ls=%ls\r\n"
        $b = "[Rename]\r\n"
    condition:
        all of them and filesize > 3287KB and filesize < 3470KB
}

rule Generic_DataStealer_1_AD83ADDF {
    meta:
        description = "Generic.DataStealer.1.AD83ADDF"
        date = "2021-08-24"
        author = "awa"
        hash1 = "2bd1cc1d9e1483c9d476331be8457cdef8cb445f8d20830fe299403e1233bb54"
    strings:
        $ = {6E 00 6F 00 74 00 20 00 72 00 65 00 63 00 6F 00 67 00 6E 00 69 00 73 00 65 00 64 00 2E 00 00 11 6D 00 61 00 78 00 56 00 61 00 6C 00 75 00 65 00 00 25 63 00 61 00 6E 00 6E 00 6F 00 74 00 20 00 62 00 65 00 20 00 6E 00 65 00 67 00 61 00 74 00 69 00 76 00 65 00 00 4B 6D 00 61 00 78 00 56 00 61 00 6C 00 75 00 65 00 20 00 63 00 61 00 6E 00 6E 00 6F 00 74 00 20 00 62 00 65 00 20 00 6C 00 65 00 73 00 73 00 20 00 74 00 68 00 61 00 6E 00 20 00 6D 00 69 00 6E 00 56 00 61 00 6C 00 75 00 65 00 00 07 20 00 3E 00 20 00 00 2F 4E 00 6F 00 74 00 20 00 61 00 6E 00 20 00 65 00 6E 00 75 00 6D 00 65 00 72 00 61 00 74 00 69 00 6F 00 6E 00 20 00 74 00 79 00 70 00 65 00 00 11 65 00 6E 00 75 00 6D 00 54 00 79 00 70 00 65 00 00 4B 63 00 69 00 70 00 68 00 65 00 72 00 20 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 61 00 20 00 62 00 6C 00 6F 00 63 00 6B 00 20 00 73 00 69 00 7A 00 65 00 20 00 6F 00 66 00 20 00 00 03 2E 00 00 09 2F 00 47 00 43 00 4D 00 00 39 49 00 6E 00 76 00 61 00 6C 00 69 00 64 00 20 00 76 00 61 00 6C 00 75 00 65 00 20 00 66 00 6F 00 72 00 20 00 4D 00 41 00 43 00 20 00 73 00 69 00 7A 00 65 00 3A 00 20 00 00 41 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 20 00 70 00 61 00 72 00 61 00 6D 00 65 00 74 00 65 00 72 00 73 00 20 00 70 00 61 00 73 00 73 00 65 00 64 00 20 00 74 00 6F 00 20 00 47 00 43 00 4D 00 00 35 49 00 56 00 20 00 6D 00 75 00 73 00 74 00 20 00 62 00 65 00 20 00 61 00 74 00 20 00 6C 00 65 00 61 00 73 00 74 00 20 00 31 00 20 00 62 00 79 00 74 00 65 00 00 4B 63 00 61 00 6E 00 6E 00 6F 00 74 00 20 00 72 00 65 00 75 00 73 00 65 00 20 00 6E 00 6F 00 6E 00 63 00 65 00 20 00 66 00 6F 00 72 00 20 00 47 00 43 00 4D 00 20 00 65 00 6E 00 63 00 72 00 79 00 70 00 74 00 69 00 6F 00 6E 00 00 4B 4B 00 65 00 79 00 20 00 6D 00 75 00 73 00 74 00 20 00 62 00 65 00 20 00 73 00 70 00 65 00 63 00 69 00 66 00 69 00 65 00 64 00 20 00 69 00 6E 00 20 00 69 00 6E 00 69 00 74 00 69 00 61 00 6C 00 20 00 69 00 6E 00 69 00 74 00 00 2D 69 00 6E 00 70 00 75 00 74 00 20 00 62 00 75 00 66 00 66 00 65 00 72 00 20 00 74 00 6F 00 6F 00 20 00 73 00 68 00 6F 00 72 00 74 00 00 2F 4F 00 75 00 74 00 70 00 75 00 74 00 20 00 62 00 75 00 66 00 66 00 65 00 72 00 20 00 74 00 6F 00 6F 00 20 00 73 00 68 00 6F 00 72 00 74 00 00 1D 64 00 61 00 74 00 61 00 20 00 74 00 6F 00 6F 00 20 00 73 00 68 00 6F 00 72 00 74 00 00 2F 6D 00 61 00 63 00 20 00 63 00 68 00 65 00 63 00 6B 00 20 00 69 00 6E 00 20 00 47 00 43 00 4D 00 20 00 66 00 61 00 69 00 6C 00 65 00 64 00 00 45 41 00 74 00 74 00 65 00 6D 00 70 00 74 00 20 00 74 00 6F 00 20 00 70 00 72 00 6F 00 63 00 65 00 73 00 73 00 20 00 74 00 6F 00 6F 00 20 00 6D 00 61 00 6E 00 79 00 20 00 62 00 6C 00 6F 00 63 00 6B 00 73 00 00 55 47 00 43 00 4D 00 20 00 63 00 69 00 70 00 68 00 65 00 72 00 20 00 63 00 61 00 6E 00 6E 00 6F 00 74 00 20 00 62 00 65 00 20 00 72 00 65 00 75 00 73 00 65 00 64 00 20 00 66 00 6F 00 72 00 20 00 65 00 6E 00 63 00 72 00 79 00 70 00 74 00 69 00 6F 00 6E 00 00 45 47 00 43 00 4D 00 20 00 63 00 69 00 70 00 68 00 65 00 72 00 20 00 6E 00 65 00 65 00 64 00 73 00 20 00 74 00 6F 00 20 00 62 00 65 00 20 00 69 00 6E 00 69 00 74 00 69 00 61 00 6C 00 69 00 73 00 65 00 64 00 00 41 4B 00 65 00 79 00 20 00 6C 00 65 00 6E 00 67 00 74 00 68 00 20 00 6E 00 6F 00 74 00 20 00 31 00 32 00 38 00 2F 00 31 00 39 00 32 00 2F 00 32 00 35 00 36 00 20 00 62 00 69 00 74 00 73 00 2E 00 00 2B 53 00 68 00 6F 00 75 00 6C 00 64 00 20 00 6E 00 65 00 76 00 65 00 72 00 20 00 67 00 65 00 74 00 20 00 68 00 65 00 72 00 65 00 00 4F 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 20 00 70 00 61 00 72 00 61 00 6D 00 65 00 74 00 65 00 72 00 20 00 70 00 61 00 73 00 73 00 65 00 64 00 20 00 74 00 6F 00 20 00 41 00 45 00 53 00 20 00 69 00 6E 00 69 00 74 00 20 00 2D 00 20 00 00 07 41 00 45 00 53 00 00 35 41 00 45 00 53 00 20 00 65 00 6E 00 67 00 69 00 6E 00 65 00 20 00 6E 00 6F 00 74 00 20 00 69 00 6E 00 69 00 74 00 69 00 61 00 6C 00 69 00 73 00 65 00 64 00 00 2F 6F 00 75 00 74 00 70 00 75 00 74 00 20 00 62 00 75 00 66 00 66 00 65 00 72 00 20 00 74 00 6F 00 6F 00 20 00 73 00 68 00 6F 00 72 00 74 00 00 07 6B 00 65 00 79}
    condition:
        all of them and filesize >= 100KB
}

rule Virus_Win95_CIH_a {
    meta:
        description = "Virus.Win95.CIH.a"
        date = "2021-08-24"
        author = "awa"
        hash1 = "512058888bddaa5b03949ec9a941feeab75ac6308d99b7fb45cad9562a028c8e"
    strings:
        $file1 = "CMPlifier052.exePK"
        $file2 = "MPlifier.batPK"
        $file3 = "MPLIFIER.PIFPK"
        $file4 = "MPlifier.txtPK"
        $file5 = "MPlifier.txt"
        $keygen2 = {77 E2 56 CA 33 83 38 99 33 83 38 99 33 83 38 99 DB 9C 32 99 08 83 38 99 B0 9F 36 99 3D 83 38 99 33 83 39 99 7D 83 38 99 51 9C 2B 99 34 83 38 99 DB 9C 33 99 31 83 38 99 8B 85 3E 99 32 83 38 99 52 69 63 68 33 83 38 99 00}
        $rar1 = "CMPlifier052.exe" ascii
        $rar2 = "MPLIFIER.BAT" ascii
        $rar4 = "del MPlifier.pif" ascii
        $rar5 = "del MPlifier.bat" ascii
    condition:
        2 of them
}

rule Worm_VBS_HappyTime_A {
    meta:
        description = "Worm.VBS.HappyTime.A"
        date = "2021-08-24"
        author = "awa"
        hash1 = "a17e1f387de381232ac6e5864035965b2c296d2f3dbf05c0e19d899c7b15db06"
    strings:
        $a = "Rem I am sorry! happy time" fullword
        $b = "HKEY_CURRENT_USER\\Identities\\"
        $c = "\\Software\\Microsoft\\Outlook Express\\5.0\\Mail"
        $d = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\DefaultProfile"
    condition:
        all of them and filesize <= 10KB
}

rule Worm_VBS_LoveLetter_A {
    meta:
        description = "Worm.VBS.LoveLetter.A"
        date = "2021-08-24"
        author = "awa"
        hash1 = "60a9509911f29cd779b7ab12ba3ccc08f87f652d626d5a581cf009e20b8c9a8e"
    strings:
        $a = "barok -loveletter(vbe) <i hate go to school>"
        $b = "by: spyder"
        $mail = "ispyder@mail.com"
        $c = "@GRAMMERSoft Group"
        $d = "Manila,Philippines"
        $e = "WIN-BUGSFIX.exe"
        $f = "WINDOWS will affect and will not run correctly. thanks"
        $g = "Khaled Mardam-Bey"
        $h = "http://www.mirc.com"
        $i = "LOVE-LETTER-FOR-YOU.HTM"
        $j = "kindly check the attached LOVELETTER coming from me"
    condition:
        all of them
}

rule Trojan_Heur_vm0_snZLJbbb {
    meta:
        description = "Trojan.Heur.vm0@sn!ZLJbbb"
        date = "2021-08-24"
        author = "awa"
        hash1 = "3919b533bbf9c9cd8aa31b7c3088d267dea8483a34383dac96480b4ff3e4524f"
    strings:
        $a = "Copyright (c) 1998 Hewlett-Packard Company"
        $b = "IEC http://www.iec.ch"
        $c = "IEC61966-2.1"
        $d = "d:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
    condition:
        all of them
}

rule Virus_Win32_Induc_A {
    meta:
        description = "Virus.Win32.Induc.A"
        date = "2021-08-24"
        author = "awa"
        hash1 = "3b64ce283febf3207dd20c99fc53de65b07044231eb544c4c41de374a2571c5c"
    strings:
        $a = "WHY YOU WANT TO CLOSE ME?"
        $b = "Tick tock, goes the clock,"
        $c = "And Now what shall we play?"
        $d = "Now Summers gone away."
        $e = "And then what shall we see?"
        $f = "Tick tock, until the day,"
        $g = "Till thou shalt marry me."
        $h = "And all the years they fly,"
        $i = "Tick tock, and all too soon,"
        $j = "You and I must die"
        $k = "I WILL HARM YOU IF YOU DOES NOT STOP!"
        $l = "HE LAST WARNING!"
        $m = "YOU MAKE YOUR CHOICE!"
        $n = "DO YOU SERIOUSLY WANT TRASH YOUR COMPUTER FOREVER?"
        $o = "666.sys"
        $p = "Windows XP Horror Edition - Created By WobbChip\r\nYoutube Channel "
    condition:
        all of them
}


rule Worm_VBS_AutoRun_A {
    meta:
        description = "Worm.VBS.AutoRun.A"
        date = "2021-08-24"
        author = "awa"
        hash1 = "b0d12dd7642e5ed3385341bd7b227e3b502754e2c5964eb48aaf2e48781f8676"
    strings:
        $d = "Rme"
        $a = "VniasuriemaN4"
    condition:
        all of them
}

rule Virus_Win32_Sola {
    meta:
        description = "Virus.Win32.Sola"
        date = "2021-08-24"
        author = "awa"
        hash1 = "f5e13e8071fecbcd2fcd29f201a2fc394269acf4319ece3c9dd18ef7e168ce69"
    strings:
        $a = "shlwapi.dll"
        $c = "YNANRC"
        $b = {44006F00630075006D0065006E007400530075006D006D0061007200790049006E0066006F0072006D006100740069006F006E000000}
        $d = {00300000003100000032000000330000003400000035000000360000003700000038000000390000003A0000003B0000003C0000003D0000003E0000003F000000400000004100000042000000430000004400000045000000460000004700000048000000490000004A0000004B0000004C0000004D0000004E0000004F000000500000005100000052000000530000005400000055000000560000005700000058000000590000005A00}
    condition:
        all of them and filesize >= 688KB
}

rule Virus_Win32_Tuza_Blamon {
    meta:
        description = "Virus.Win32.Tuza.Blamon"
        date = "2021-08-24"
        author = "awa"
        hash1 = "189bdd9d225537cdd803931a50eb308f6a952259fb74768879aa44df7648e222"
    strings:
        $a = "d09f2340818511d396f6aaf844c7e325"
        $b = "F7FC1AE45C5C4758AF03EF19F18A395D"
        $c = "AVtype_info"
        $f = "Control Panel\\Desktop"
        $d = "TileWallpaper"
        $e = "XPADDINGPADDINGX"
    condition:
        all of them
}


rule Trojan_Win32_FormatAll {
    meta:
        description = "Trojan.Win32.FormatAll"
        date = "2021-08-24"
        author = "awa"
        hash1 = "a2da77f846946cffb8ecb05fa9010aef74b199ee0c66cb7f241a3f998e0c31ae"
    strings:
        $a = "%s.%d.tmp"
        $b = "%s %s %s"
        $c = "YNANRC"
        $d = {69 6E 67 63 68 75 2E 62 61 74}
    condition:
        all of them
}


rule Trojan_Win32_Tuza_Disabler {
    meta:
        description = "Trojan.Win32.Tuza.Disabler"
        date = "2021-08-25"
        author = "awa"
        hash1 = "189bdd9d225537cdd803931a50eb308f6a952259fb74768879aa44df7648e222"
    strings:
        $a = "\\a\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\b\\v\\t\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v\\v"
        $b = "\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v6\\v3\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v,\\v%\\v%\\v%\\v%\\v%\\v%\\v%\\v%\\v%\\v%\\v%\\v+\\v+\\v+\\v+\\v+\\v+\\v+"
    condition:
        all of them
}

rule Worm_VBS_yuyun_A {
    meta:
        description = "Worm.VBS.yuyun.A"
        date = "2021-08-25"
        author = "awa"
        hash1 = "3d929fbd23378f3246f6643f503e48ae8ece5bdd8899e7ddf86568ebd044a2f2"
    strings:
        $url = "www.muslimah.or.id"
        $by = "my name:Yuyun 1.0"
        $a = "66666666*5555*4444*3333*222222222222z"
    condition:
        all of them
}

rule Win32_Evo_gen {
    meta:
        description = "Win32.Evo-gen"
        date = "2021-08-25"
        author = "awa"
        hash1 = "7936deb5e6a236e8dce91352d0617e3db3bbe0fbaeba5fb08bbeac7590338c4d"
    strings:
        $a = "VirtualProtect"
        $b = "GetAdaptersInfo"
        $c = "BitBlt"
        $d = {77 63 73 63 6D 70 00 00 00 53 48 53 65 74 56 61 6C 75 65 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 45 78 41 00 00 00 47 65 74 41 64 61 70 74 65 72 73 49 6E 66 6F 00 00 00 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 41 00 00 00 44 65 73 74 72 6F 79 45 6E 76 69 72 6F 6E 6D 65 6E 74 42 6C 6F 63 6B 00 00 00 47 64 69 70 47 65 74 49 6D 61 67 65 45 6E 63 6F 64 65 72 73 53 69 7A 65 00 00 00 47 65 74 44 43 00 00 00 42 69 74 42 6C 74 00 00 00 53 65 74 45 6E 74 72 69 65 73 49 6E 41 63 6C 41 00 00 00 53 48 47 65 74 53 70 65 63 69 61 6C 46 6F 6C 64 65 72 50 61 74 68 41}
    condition:
        all of them
}

rule Virus_Win32_disttrack_A {
    meta:
        description = "Virus.Win32.disttrack.A"
        date = "2021-08-25"
        author = "awa"
        hash1 = "4f02a9fcd2deb3936ede8ff009bd08662bdb1f365c0f4a78b3757a98c2f40400"
    strings:
        $c = "c:\\windows\\temp\\out17626867.txt" fullword
    condition:
        2 of them
}

rule Worm_Win32_WHBOY_Viking_A {
    meta:
        description = "Worm.Win32.WHBOY.Viking.A"
        date = "2021-08-25"
        author = "awa"
        hash1 = "40fee2a4be91d9d46cc133328ed41a3bdf9099be5084efbc95c8d0535ecee496"
    strings:
        $WHBOY = "WHBOY" nocase
        $setup = "GameSetup.exe"
    condition:
        all of them
}

rule Net_Worm_Win32_Blaster_A {
    meta:
        description = "Net-Worm.Win32.Blaster.A"
        date = "2021-08-25"
        author = "awa"
        hash1 = "4fac23655b6c0925a697d4814a20a11f901aa724f7f9cb7d22eae28303156fbd"
    strings:
        $a = "msblast.exe"
        $b = "say LOVE YOU SAN!!"
        $c = "! Antivirus NOT work ! w32.Blaster.Worm bei testvirus.de"
    condition:
        2 of them
}

rule Net_Worm_Win32_Sasser_A {
    meta:
        description = "Net-Worm.Win32.Sasser.A"
        date = "2021-08-25"
        author = "awa"
        hash1 = "09398d3f5cc102f7d932b765036e1ac1ff5dc27405d7357b81eaf48ca8ec71b8"
    strings:
        $a = {6E 74 72 79 20 50 6F 69 6E 74 20 4E 6F 74 00 00 20 46 6F 75 6E 64 00 54 68 65 20 70 72 6F 63 65 0C 03 64 75 72 65 20 65}
        $b = {63 6F 75 6C 64 20 6E 6F 74 20 62 65 00 00 20 6C 6F 63 61 74 65 64 20 69 6E 20 74 68 65 20 00 00 64 79 6E 61 6D 69 63 20 6C 69 6E 6B 20}
    condition:
        all of them
}

rule Worm_Win32_Ramnit {
    meta:
        description = "Worm.Win32.Ramnit"
        date = "2021-08-25"
        author = "awa"
        hash1 = "bc8745a3434ca183ec03aa3ac608b31f642c563f5038e24816014cb13054b1e1"
    strings:
        $a = "d09f2340818511d396f6aaf844c7e325"
        $b = "27bb20fdd3e145e4bee3db39ddd6e64c"
        $c = "5F99C1642A2F4e03850721B4F5D7C3F8"
        $d = "DA19AC3ADD2F4121AAD84AC5FBCAFC71"
        $e = "qdZRMHD@=;86421/.-+*)(''&%$$#\"\"!!  "
    condition:
        all of them
}

rule Worm_Win32_Xorer_A {
    meta:
        description = "Worm.Win32.Xorer.A"
        date = "2021-08-25"
        author = "awa"
        hash1 = "e60e684986ec4f5c9d6c81109a5ac41a9254cdfdc08734fa4ae30596dc8fbf42"
    strings:
        $a = "NetApi00DOS"
        $b = "twter"
    condition:
        all of them
}

rule Worm_Win32_Pabug {
    meta:
        description = "Worm.Win32.Pabug"
        date = "2021-08-25"
        author = "awa"
        hash1 = "53416af57802d87162b4733d900e90d6b289100b7f88d30c0f9b4debe76cee15"
    strings:
        $a = "hijklmno/pq"
        $b = "LMNOPQR PU"
        $c = "GHIJK"
    condition:
        all of them
}

rule Trojan_Win32_Dogrobot {
    meta:
        description = "Trojan.Win32.Dogrobot"
        date = "2021-08-25"
        author = "awa"
        hash1 = "6da755250f12f2ded94cc549bb085107eb56ab7ba22f70f0e5766885ba4ac566"
    strings:
        $a = {53 45 52 33 32 2E 64 6C E3 C0 6B 65 39 72 6E F8 A6 0D 75 61 73 76 23 70 69 9C 01 0E 20 40 03 4D 65 73 89 61 67 D4 42 6F 38 78 41 70 67 28 23 47 C3 74 4D E8 64 75 6C EE 48 37 61 6E 4C DC 2C 47 F7 FD 62 EF FF 8D 62 DD 63 4C 0C 46 38 72 65 F0 7F 4C CD 9A 52 7A D9 75 F5 63 47 0D 54 6B 2C 46 77 6C F4 68 EA 69 CF 78 42 EE 66 3B FC E7 0D 34 A0 56 10 CE 12 74 AC 5A 22 6F CE E8 6D 9D 9C 79 19 53 D4 45 8A C6 4F 66 1B B4 1B 07 08 50 6F D7 6E 9D 46 BE 1E 3E 7A 7B 57 66 53 3A 57 B4 69 2C 59 28 0A 6E 5D 77 00 9C 45 78 70 AB A6 1B 8C 76 69 AC C1 6D 65 9C 76 53 B7 54 E2 67 73 8C 1A 64 50 CA 2A 63 DF B8 3A 44 EC 40 12 49 FA 43 DB 48 3E B3 6C 68 21 92 4F 4C 50 43 A1 CC 61 5D 0C 02 DE 73 BB F7 80 4F 75 74 6C 70 06 54 62 F0 67 A4 54 A9 1F 08 16 1A 7E 61 D0 CC A2 41 52 8D 26 4F 70 E8 1A 0D 1A 43 4D 80 A7 50 72 FA 66 68 1E 68 68 68 2C E8 8B E8 1E ED F5 19 1D}
    condition:
        any of them
}

rule Trojan_Ransomware_MineCraft {
    meta:
        description = "Trojan.Ransomware.MineCraft"
        date = "2021-08-25"
        author = "awa"
        hash1 = "2b0ca9f08e41c4700478ca4cd8fcbcc2c39b6b2e7b19c3b1393470376578b63d"
        Decrypt = "https://www.aliyundrive.com/s/g7qGZ5hJqsg"
    strings:
        $java = "cmd /c taskkill /im java.exe /f"
        $javaw = "cmd /c taskkill /im javaw.exe /f"
        $filename = "\\desktop\\minecraftcry.exe"
        $url = "cmd /c c:\\windows\\temp\\microminiforwebbrowserold.exe /https://mdownload.mini1.cn/latest/miniworldoffice.exe"
    condition:
        all of them
}

rule Trojan_XUQINGEN {
    meta:
        description = "Trojan.XUQINGEN"
        date = "2021-08-25"
        author = "awa"
        hash1 = "567e3d8b273eda65752de6cd0dc54e4d1696639bad1a7d8cef4a8cfb3df968e1"
    strings:
        $video = "c:\\windows\\1.MP4"
        $a = "{6AEDBD6D-3FB5-418A-83A6-7F45229DC872}"
        $runtime = "Microsoft Visual C++ Runtime Library"
    condition:
        all of them
}

rule Trojan_Win32_MBRlock{
    meta:
        description = "Trojan.Win32.MBRlock"
        date = "2021-08-25"
        author = "awa"
        hash1 = "99eb4bf51d546cc27e8c60aaddd6ed0b517b181ddda0f1005f7d4d0278a28dfb"
    strings:
        $a = "18511d396f6aaf844c7eT5"
        $b = {70 74 46 B8 23 74 46 B8 23 74 46 B8 23 0F 5A B4 23 71 46 B8 23 1B 59 B3 23 7D 46 B8 23 1B 59 B2 23 72 46 B8 23 F7 5A B6 23 58 46 B8 23 22 59 AB 23 58 46 B8 23 16 59 AB 23 62 46 B8 23 74 46 B9 23 EC 44 B8 23 F7 4E E5 23 76 46 B8 23 42 60 B3 23 2F 46 B8 23 42 60 B2 23 A0 46 B8 23 9C 59 B3 23 2F 46 B8 23 9C 59 B2 23 6F 46 B8 23 74 46 B8 23 BF 46 B8 23 B3 40 BE 23 75 46 B8 23 52 69 63 68 74 46 B8 23 00 00}
    condition:
        all of them
}


rule BackDoor_SiggenNET_23 {
    meta:
        description = "BackDoor.SiggenNET.23"
        date = "2021-09-11"
        author = "awa"
        hash1 = "124023c0cf0524a73dabd6e5bb3f7d61d42dfd3867d699c59770846aae1231ce"
    strings:
        $a = "reloc"
        $b = {24 62 66 35 38 66 63 32 63 2D 36 66 36 35 2D 34 33 36 64 2D 38 66 31 65 2D 32 61 31 62 39 35 37 36 32 38 66 37}
        $c = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39}
    condition:
        all of them
}

rule Power_base64 {
    meta:
        description = "Power.base64.a"
        date = "2021-09-13"
        author = "awa"
        hash1 = "706107bf69a4e8c4d253c1395c500c17f5c79d7991d5f4060cc227f70d7f053a"
    strings:
        $a = {5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C}
        $b = {50 53 4C 65 73 73 00 6D 73 63 6F 72 6C 69 62 00 53 79 73 74 65 6D 00 4F 62 6A 65 63 74 00 4D 61 69 6E 00 42 61 73 65 36 34 44 65 63 6F 64 65 00 52 75 6E 53 63 72 69 70 74 00 2E 63 74 6F 72 00 61 72 67 73 00 73 00 73 63 72 69 70 74 00 53 79 73 74 65 6D 2E 52 75 6E 74 69 6D 65 2E 43 6F 6D 70 69 6C 65 72 53 65 72 76 69 63 65 73 00 43 6F 6D 70 69 6C 61 74 69 6F 6E 52 65 6C 61 78 61 74 69 6F 6E 73 41 74 74 72 69 62 75 74 65 00 52 75 6E 74 69 6D 65 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 41 74 74 72 69 62 75 74 65 00 70 6F 77 65 72 5F 62 61 73 65 36 34 00 45 6E 76 69 72 6F 6E 6D 65 6E 74 00 45 78 69 74 00 43 6F 6E 73 6F 6C 65 00 57 72 69 74 65 4C 69 6E 65 00 43 6F 6E 73 6F 6C 65 4B 65 79 49 6E 66 6F 00 52 65 61 64 4B 65 79 00 53 79 73 74 65 6D 2E 54 65 78 74 00 45 6E 63 6F 64 69 6E 67 00 67 65 74 5F 44 65 66 61 75 6C 74 00 43 6F 6E 76 65 72 74 00 46 72 6F 6D 42 61 73 65 36 34 53 74 72 69 6E 67 00 47 65 74 53 74 72 69 6E 67 00 53 79 73 74 65 6D 2E 4D 61 6E 61 67 65 6D 65 6E 74 2E 41 75 74 6F 6D 61 74 69 6F 6E 00 53 79 73 74 65 6D 2E 4D 61 6E 61 67 65 6D 65 6E 74 2E 41 75 74 6F 6D 61 74 69 6F 6E 2E 52 75 6E 73 70 61 63 65 73 00 52 75 6E 73 70 61 63 65 46 61 63 74 6F 72 79 00 52 75 6E 73 70 61 63 65 00 43 72 65 61 74 65 52 75 6E 73 70 61 63 65 00 4F 70 65 6E 00 50 69 70 65 6C 69 6E 65 00 43 72 65 61 74 65 50 69 70 65 6C 69 6E 65 00 43 6F 6D 6D 61 6E 64 43 6F 6C 6C 65 63 74 69 6F 6E 00 67 65 74 5F 43 6F 6D 6D 61 6E 64 73 00 41 64 64 53 63 72 69 70 74 00 41 64 64 00 53 79 73 74 65 6D 2E 43 6F 6C 6C 65 63 74 69 6F 6E 73 2E 4F 62 6A 65 63 74 4D 6F 64 65 6C 00 43 6F 6C 6C 65 63 74 69 6F 6E 60 31 00 50 53 4F 62 6A 65 63 74 00 49 6E 76 6F 6B 65 00 43 6C 6F 73 65 00 53 74 72 69 6E 67 42 75 69 6C 64 65 72 00 53 79 73 74 65 6D 2E 43 6F 6C 6C 65 63 74 69 6F 6E 73 2E 47 65 6E 65 72 69 63 00 49 45 6E 75 6D 65 72 61 74 6F 72 60 31 00 47 65 74 45 6E 75 6D 65 72 61 74 6F 72 00 67 65 74 5F 43 75 72 72 65 6E 74 00 54 6F 53 74 72 69 6E 67 00 41 70 70 65 6E 64 4C 69 6E 65 00 53 79 73 74 65 6D 2E 43 6F 6C 6C 65 63 74 69 6F 6E 73 00 49 45 6E 75 6D 65 72 61 74 6F 72 00 4D 6F 76 65 4E 65 78 74 00 49 44 69 73 70 6F 73 61 62 6C 65 00 44 69 73 70 6F 73 65 00 00 00 15 4F 00 75 00 74 00 2D 00 53 00 74 00 72 00 69 00 6E 00 67}
    condition:
        all of them
}

rule Application_BadJoke_G {
    meta:
        description = "Trojan.WinXPHorror"
        date = "2021-09-19"
        author = "awa"
        hash1 = "350f397360397a8607613390ffae51dca3c35a2e92659db03ba6ef23f3704740"
    strings:
        $a = "Setup cannot copy the file ntdll.dll\r\nSetup will use the file 666.sys"
        $b = "%s%s%s%s%s%s%s%s%s%s"
        $c = "WHY YOU WANT TO CLOSE ME?"
        $d = "Tick tock, goes the clock,"
        $e = "And Now what shall we play?"
        $f = "Now Summers gone away."
        $g = "And then what shall we see?"
        $h = "Tick tock, until the day,"
        $i = "Till thou shalt marry me."
        $j = "And all the years they fly,"
        $k = "Tick tock, and all too soon,"
        $l = "You and I must die"
        $m = "I WILL HARM YOU IF YOU DOES NOT STOP!"
        $n = "THE LAST WARNING!"
        $o = "YOU MAKE YOUR CHOICE!"
    condition:
        all of them
}

rule Trojan_Win32_PurpleFox {
    meta:
        description = "Trojan.Win32.PurpleFox"
        date = "2021-10-04"
        author = "awa"
        hash1 = "27178fb7aad699704a08b90b79f4768de6fc85efd2361929256e528841e03270"
    strings:
        $a = "F59C15B-606F-41F0-A8C1-1BCB429C7AB7}"
        $b = "\t\t\t\t\\b\\b\\b\\b\\b\\b\\b\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a"
        $c = "JobRelease\\win\\Release\\custact\\x86\\AICustAct.pdb"
        $d = "\\JobRelease\\win\\Release\\custact\\x86\\Prereq.pdb"
    condition:
        2 of them
}

rule Worm_Win32_Bototer {
    meta:
        description = "Worm.Win32.Bototer"
        date = "2021-10-05"
        author = "awa"
        hash1 = "2a78a8a9bae302f1f588d5ad056f33d0fb23d5af1d37b53d9bbe93faa7bbdd2c"
    strings:
        $a = "www.3-0B6F-415d-B5C7-832F0.com"
        $b = "GET %s?%s HTTP/1.1\r\nConnection: Keep-Alive\r\nHost: %s\r\nUser-Agent: Mozilla/4.0\r\nAccept-language: cn\r\n\r\n"
        $c = "96DBA249-E88E-4c47-98DC-E18E6E3E3E5A"
        $d = "%s\\desktop.txt"
        $e = "recycle.{645FF040-5081-101B-9F08-00AA002F954E}"
    condition:
        all of them
}

rule Worm_Win32_Almanahe_A {
    meta:
        description = "Worm.Win32.Almanahe.A"
        date = "2021-10-05"
        author = "awa"
        hash1 = "7af31f54a8e40383b247abaadbf239e001cc1c728059470ef910ccbe5164ab22"
    strings:
        $a = "\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a"
        $b = "!^!Z!V!R!F!B!~!z!v!r!n!j!f!b!"
        $c = "ppqj>|{>lkp>wp>ZQM>sqz{0"
    condition:
        2 of them
}

rule Worm_Win32_AutoRun_ttry_A {
    meta:
        description = "Worm.Win32.AutoRun.ttry.A"
        date = "2021-10-05"
        author = "awa"
        hash1 = "78ffae9c11f885e7b0834ec8f5da1de141a77b5de695164fbb1ba85881fac13e"
    strings:
        $a = "C:\\windows\\ttry.exe"
        $b = "C:\\windows\\tsay.exe"
        $c = "XwwwwwwwwwwwwwwSSSTTpNJBllll"
    condition:
        all of them
}

rule Worm_Win32_Neshta_A {
    meta:
        description = "Worm.Win32.Neshta.A"
        date = "2021-10-05"
        author = "awa"
        hash1 = "980bac6c9afe8efc9c6fe459a5f77213b0d8524eb00de82437288eb96138b9a2"
    strings:
        $a = "FPUMaskValue"
        $b = {44 65 6C 70 68 69 2D 74 68 65 20 62 65 73 74 2E 20 46 75 63 6B 20 6F 66 66 20 61 6C 6C 20 74 68 65 20 72 65 73 74 2E 20 4E 65 73 68 74 61 20 31 2E 30 20 4D 61 64 65 20 69 6E 20 42 65 6C 61 72 75 73 2E}
    condition:
        all of them
}


rule Virus_Win32_Synaptic_A {
    meta:
        description = "Virus.Win32.Synaptic.A"
        date = "2021-12-19"
        author = "awa"
        hash1 = "3f76784d4716ce6cd03f91bdb5d61a4c00552d33597666d29ea81cb4a8a6c052"
    strings:
        $name = "Synaptics"
        $b = "Synaptics Pointing Device Driver"
        $link1 = "http://freedns.afraid.org/api/?action=getdyndns&sha=a30fa98efc092684e8d1c5cff797bcc613562978"
        $link2 = "https://docs.google.com/uc?id=0BxsMXGfPIZfSVlVsOGlEVGxuZVk&export=download"
        $link3 = "https://www.dropbox.com/s/n1w4p8gc6jzo0sg/SUpdate.ini?dl=1"
        $link4 = "http://xred.site50.net/syn/SUpdate.ini"
    condition:
        all of them
}

rule Separatists_Virus_V2 {
    meta:
        description = "Separatists.Virus.V2"
        date = "2021-12-19"
        author = "awa"
        hash1 = "5d03f37231b5310b032ddf6d4d3a35b0ce8dee057ba83435a63c4291c46105fb"
    strings:
        $a = {83 58 F6 39 DD 02 00 00 00 00 38}
    condition:
        any of them
} 

rule Smile_jpg {
    meta:
        description = "Smile.jpg"
        date = "2021-12-21"
        author = "awa"
        hash1 = "b9625d91eb806513cac337a24ce5d8fe0b170554976b77fb1f2dad3981358f78"
    strings:
        $text = "正在销毁系统"
        $reg1 = "software\\microsoft\\windows\\CurrentVersion\\Run\\kiss770.cn\\"
        $taskkill1 = "taskkill /f /im kavsvc.exe"
        $taskkill2 = "taskkill /f /im KVXP.kxp"
        $taskkill3 = "taskkill /f /im Rav.exe"
        $taskkill4 = "taskkill /f /im Ravmon.exe"
        $taskkill5 = "taskkill /f /im Mcshield.exe"
        $taskkill6 = "taskkill /f /im VsTskMgr.exe"
        $sb3601 = "SOFTWARE\\360Safe\\safemon\\ExecAccess"
        $sb3602 = "SOFTWARE\\360Safe\\safemon\\MonAccess"
        $sb3603 = "SOFTWARE\\360Safe\\safemon\\SiteAccess"
        $sb3604 = "SOFTWARE\\360Safe\\safemon\\UDiskAccess"
        $sb3605 = "taskkill /f /im 360tray.exe"
        $file = "jpegfile"
        $text2 = "I Love YOU!"
    condition:
        6 of them
}

rule DiskLock {
    meta:
        description = "DiskLock"
        date = "2021-12-21"
        author = "awa"
        hash1 = "e87dd96e36ec03b114a122eacc1bec6fc094390d98d5b6afd1e8dc27e0b94b48"
    strings:
        $pdbpath = "C:\\Users\\leo20\\source\\repos\\DiskLock\\Release\\DiskLock.pdb"
        $b = "?5Wg4p"
    condition:
        all of them
}

rule Ransom_000 {
    meta:
        description = "Ransom.000"
        date = "2022-01-10"
        author = "awa"
        hash1 = "4ea1f2ecf7eb12896f2cbf8683dae8546d2b8dc43cf7710d68ce99e127c0a966"
    strings:
        $a = {50 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 50 41 44 44 49 4E 47 58 58 50 41 44}
        $pdb = {43 3A 5C 55 73 65 72 73 5C 46 6C 79 54 65 63 68 5C 44 6F 63 75 6D 65 6E 74 73 5C 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 32 30 31 35 5C 50 72 6F 6A 65 63 74 73 5C 4D 65 73 73 61 67 65 72 5C 4D 65 73 73 61 67 65 72 5C 6F 62 6A 5C 44 65 62 75 67 5C 4D 65 73 73 61 67 65 72 2E 70 64 62}
        $b = {50 41 4D 5A}
    condition:
        all of them
}

rule Virus_Win32_Floxif_a {
    meta:
        description = "Virus.Win32.Floxif.a"
        date = "2022-02-08"
        author = "awa"
        hash1 = "6842ada96f7d11938aa70a3124fc14d7c9f6cacaf9fa52b2dbd26a9b7d5fb899"
    strings:
        $a = "-64OS"
        $b = {C7 3C 71 39 83 5D 1F 6A 83 5D 1F 6A 83 5D 1F 6A 3E 12 89 6A 82 5D 1F 6A 8A 25 8A 6A 9A 5D 1F 6A 8A 25 9C 6A 18 5D 1F 6A 8A 25 9B 6A BF 5D 1F 6A A4 9B 72 6A 84 5D 1F 6A A4 9B 64 6A 9C 5D 1F 6A 83 5D 1E 6A 94 5C 1F 6A 8A 25 95 6A 8C 5D 1F 6A 8A 25 8D 6A 82 5D 1F 6A 9D 0F 8B 6A 82 5D 1F 6A 8A 25 8E 6A 82 5D 1F 6A 52 69 63 68 83 5D 1F 6A}
        $c = {E8 68 FA FF FF FF}
        $d = {41 56 62 61 64 5F 65 78 63 65 70 74 69 6F 6E 40 73 74 64}
    condition:
        all of them
}

rule Virus_Win32_Floxif_b {
    meta:
        description = "Virus.Win32.Floxif.b"
        date = "2022-02-08"
        author = "awa"
        hash1 = "eda99d18ec436be103b42766916e27ae66e444aa2e48436f9a249c93efb50829"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{B69F34DD-F0F9-42DC-9EDD-957187DA688D}"
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE"
        $reg3 = "CLSID\\{B69F34DD-F0F9-42DC-9EDD-957187DA688D}\\InprocServer32"
        $reg4 = "Internet Explorer\\IEXPLORE.EXE" nocase
        $url1 = "HTTP://*.BAIDU.COM/S*" nocase
        $url2 = "HTTP://*.GOOGLE.COM.HK/SEARCH*" nocase
        $url3 = "HTTP://*.SOSO.COM/Q*" nocase
        $url4 = "HTTP://CN.BING.COM/SEARCH*" nocase
        $url = "biz.com.edu.gov.info.int.mil.name.net.org.pro.aero.cat.coop.jobs.museum.travel.arpa.root.mobi.post.tel.asia.geo.kid.mail.sco.web.xxx.nato.example.invalid.test.bitnet.csnet.onion.uucp.xn--0zwm56d.xn--g6w251d" nocase
    condition:
        3 of them
}

rule Ransom_Win32_FRSCryptor {
    meta:
        description = "Ransom.Win32.FRSCryptor"
        date = "2022-07-01"
        hash1 = "72ebc223bef1bf4cabad9c7eb6e520f0d93554f2807d4c8875be24dc3ab129a4"
    strings:
        $a = {4D 73 00 00 60 2D 4A 00 6C 2D 4A 00 54 2D 4A}
        $b = {47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 6F 6C 65 61 75 74 33 32 2E 64 6C 6C 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 61 64 76 61 70 69 33 32 2E 64 6C 6C 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 43 68 61 72 4E 65 78 74 41 00 53 48 46 6F 6C 64 65 72 2E 64 6C 6C 00 00 00 53 48 47 65 74 46 6F 6C 64 65 72 50 61 74 68 41}
    condition:
        all of them
}
