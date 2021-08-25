import "pe"

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
        description = "Backdoor.CobaltStrike"
        author = "awa"
        date = "2021-08-04"
    strings:
        $ = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
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
        $keygen1 = "Keygenerator by SlaSk/FALLEN"
        $keygen2 = "Internet Audio Mix v1.14"
        $rar1 = "CMPlifier052.exe" ascii
        $rar2 = "MPLIFIER.BAT" ascii
        $rar3 = "MICROSOFT PIFEX" ascii
        $rar4 = "del MPlifier.pif" ascii
        $rar5 = "del MPlifier.bat" ascii
        $rar6 = "http://www.kagi.com/authors/giunti/\r\n"
        $rar7 = "Internet: giunti@kagi.com\r\n"
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
    condition:
        any of them
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
        $b = "WinRAR SFX"
        $c = "*messages***"
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
        $a = "*messages***"
        $b = "%s %s %s"
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
        $a = "Wow64DisableWow64FsRedirection"
        $b = "Wow64RevertWow64FsRedirection"
        $c = "c:\\windows\\temp\\out17626867.txt"
        $d = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED."
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
        $a = "inflate 1.1.3 Copyright 1995-1998 Mark Adler "
        $b = "deflate 1.1.3 Copyright 1995-1998 Jean-loup Gailly "
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

rule Trojan_Ransomware_MiniWorld {
    meta:
        description = "Trojan.Ransomware.MiniWorld"
        date = "2021-08-25"
        author = "awa"
        hash1 = "24a163dbbbd12e458bcbcfa3e9707da5c7364369060344f062ef46dbf208169d"
    strings:
        $b = "inflate 1.2.8 Copyright 1995-2013 Mark Adler "
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