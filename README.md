## Information
This is a simple tool to utilize the basic functionality of the Private API From Virus Total, with this tool you can eaisly scan a hash or file (script will automatically hash the file and submit the HASH to VT not the file). You can download malware based on hash, download pcaps, write the full VT Json report to file, and force a rescan of a previously uploaded file with new AV definitions. Advanced queries and bulk downloads can be accomplished via VT Provided Scripts available on the Intelligence portal. (or a bash loop if you want to bulk DL with this)

NOTE: You need your own premium VT API to use this tool. API Key Goes on Line 13!

NOTE2: If you have a free VT Public API (you do) then you can use VTlite.py with limited functionality (Check Hash/Path/Rescan/DownloadJson/VerboseDetections) four checks per minute are allowed.

## Authors & Licence
Original Script Author: Adam Meyers

Rewritten & Modified: Chris Clark

License: Do whatever you want with it :)

## Example
<pre>
Usage is as follows with an example of a basic search +  hitting all of
the switches below:

usage: vt.py [-h] [-s] [-v] [-j] [-d] [-p] [-r] HashorPath

Search and Download from VirusTotal

positional arguments:
 HashorPath      Enter the MD5 Hash or Path to File

optional arguments:
 -h, --help      show this help message and exit
 -s, --search    Search VirusTotal
 -v, --verbose   Turn on verbosity of VT reports
 -j, --jsondump  Dumps the full VT report to file (VTDLXXX.json)
 -d, --download  Download File from Virustotal (VTDLXXX.danger)
 -p, --pcap      Download Network Traffic (VTDLXXX.pcap)
 -r, --rescan    Force Rescan with Current A/V Definitions

Example Basic Scan:

xen0ph0n@pir8ship:~/tools$ python vt.py ../../VirtualBox_Share/wsusservice.dll -s

      Results for MD5:  92d37a92138659fa75f45ccb87242910

      Detected by:  30 / 43
      Sophos Detection: Troj/Briba-A
      Kaspersky Detection: Backdoor.Win32.Agent.clfe
      TrendMicro Detection: BKDR_BRIBA.A
      Scanned on: 2012-09-28 02:44:37
      First Seen: 2012-08-15 12:36:02
      Last Seen: 2012-09-28 02:44:37
      Unique Sources 3
      Submission Names:
            92d37a92138659fa75f45ccb87242910
            wsusservice.dll_
            wsusservice2.dll_
            file-4567337_



Example Verbose Scan + Download + Pcap + Json Save + Force Rescan:

xen0ph0n@pir8ship:~/tools$ python vt.py 287f3dda64b830a5ac5a6df3266f7d08 -pdvjr

      Results for MD5:  287f3dda64b830a5ac5a6df3266f7d08

      Detected by:  38 / 46
      Sophos Detection: Troj/Hurgyu-A
      Kaspersky Detection: Trojan-Dropper.Win32.Dapato.bnnu
      TrendMicro Detection: TROJ_GEN.RCBC8HQ
      Scanned on: 2013-03-25 21:38:35
      First Seen: 2012-09-25 09:14:13
      Last Seen: 2012-09-25 09:14:13
      Unique Sources 1
      Submission Names:
            7DkduxxH

       JSON Written to File -- VTDL287F3DDA64B830A5AC5A6DF3266F7D08.json

       Verbose VirusTotal Information Output:

       MicroWorld-eScan         True     Trojan.Generic.7705996
       nProtect                 True     Trojan/W32.Small.29184.SN
       CAT-QuickHeal            True     TrojanDropper.Dapato.bnnu
       McAfee                   True     Generic Dropper!ff3
       Malwarebytes             True     Trojan.Inject
       K7AntiVirus              True     Riskware
       TheHacker                False    None
       NANO-Antivirus           True     Trojan.Win32.Dapato.vpmxh
       F-Prot                   False    None
       Symantec                 True     Trojan.Gen.2
       Norman                   True     Suspicious_Gen4.AWDSR
       TotalDefense             False    None
       TrendMicro-HouseCall     True     TROJ_GEN.RCBC8HQ
       Avast                    True     MX97:ShellCode-I [Expl]
       eSafe                    False    None
       ClamAV                   False    None
       Kaspersky                True     Trojan-Dropper.Win32.Dapato.bnnu
       BitDefender              True     Trojan.Generic.7705996
       Agnitum                  True     Trojan.DR.Dapato!qkvVtOGNQlE
       SUPERAntiSpyware         False    None
       Emsisoft                 True     Trojan.Generic.7705996 (B)
       Comodo                   True     UnclassifiedMalware
       F-Secure                 True     Trojan:W32/Agent.DUDB
       DrWeb                    True     Trojan.DownLoader6.49674
       VIPRE                    True     Trojan.Win32.Generic!BT
       AntiVir                  True     TR/Agent.29184.170
       TrendMicro               True     TROJ_GEN.RCBC8HQ
       McAfee-GW-Edition        True     Generic Dropper!ff3
       Sophos                   True     Troj/Hurgyu-A
       Jiangmin                 True     TrojanDropper.Dapato.mfq
       Antiy-AVL                True     Trojan/Win32.Dapato.gen
       Kingsoft                 True     Win32.Troj.Dapato.(kcloud)
       Microsoft                True     VirTool:Win32/Obfuscator.ABD
       ViRobot                  True     Dropper.A.Dapato.29184.J
       AhnLab-V3                True     Trojan/Win32.Inject
       GData                    True     Trojan.Generic.7705996
       Commtouch                False    None
       ByteHero                 False    None
       VBA32                    True     Trojan-Dropper.Dapato.bnnu
       PCTools                  True     Trojan.Gen
       ESET-NOD32               True     a variant of Win32/Inject.NFV
       Rising                   True     Suspicious
       Ikarus                   True     Win32.SuspectCrc
       Fortinet                 True     W32/Inject.NFV!tr
       AVG                      True     Dropper.Generic6.APFX
       Panda                    True     Generic Trojan

       Malware Downloaded to File -- VTDL287F3DDA64B830A5AC5A6DF3266F7D08.danger

       PCAP Downloaded to File -- VTDL287F3DDA64B830A5AC5A6DF3266F7D08.pcap

       Virus Total Rescan Initiated for -- 287F3DDA64B830A5AC5A6DF3266F7D08 (Requery in 10 Mins)
</pre>
