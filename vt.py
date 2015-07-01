#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity
# If things are broken let me know chris@xenosec.org
# No Licence or warranty expressed or implied, use however you wish! 

import json, urllib, urllib2, argparse, hashlib, re, sys
from pprint import pprint

class vtAPI():
    def __init__(self):
        self.api = '<--------------PUBLIC-API-KEY-GOES-HERE----->'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api,'allinfo': '1'}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata
    
    def downloadFile(self,md5,name):
      try:
        param = {'hash':md5,'apikey':self.api}
        url = self.base + "file/download"
        data = urllib.urlencode(param)
        req = urllib2.Request(url,data)
        result = urllib2.urlopen(req)
        downloadedfile = result.read()
        if len(downloadedfile) > 0:
          fo = open(name,"wb")
          fo.write(downloadedfile)
          fo.close()
          print "\n\tMalware Downloaded to File -- " + name
        else:
          print md5 + " -- Not Found for Download"
      except Exception:
        print md5 + " -- Not Found for Download"

    def downloadPcap(self,md5,name):
      try:
        req = urllib2.Request("https://www.virustotal.com/vtapi/v2/file/network-traffic?apikey="+self.api+"&hash="+md5)
        result = urllib2.urlopen(req)
        pcapfile = result.read()
        if len(pcapfile) > 0 and '{"response_code": 0, "hash":' not in pcapfile :
          fo = open(name,"wb")
          fo.write(pcapfile)
          fo.close()
          print "\n\tPCAP Downloaded to File -- " + name
        else:
          print md5 + " -- PCAP Not Available"
      except Exception:
        print md5 + " -- PCAP Not Available"
    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"


# Md5 Function

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 
          
def parse(it, md5, verbose, jsondump):
  if it['response_code'] == 0:
    print md5 + " -- Not Found in VT"
    return 0
  print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n\tSophos Detection:',it['scans']['Sophos']['result'] ,'\n\tKaspersky Detection:',it['scans']['Kaspersky']['result'], '\n\tTrendMicro Detection:',it['scans']['TrendMicro']['result'],'\n\tScanned on:',it['scan_date'],'\n\tFirst Seen:',it['first_seen'],'\n\tLast Seen:',it['last_seen'],'\n\tUnique Sources',it['unique_sources'],'\n\tSubmission Names:'
  for x in it['submission_names']:
    print "\t\t",x
  if jsondump == True:
    jsondumpfile = open("VTDL" + md5 + ".json", "w")
    pprint(it, jsondumpfile)
    jsondumpfile.close()
    print "\n\tJSON Written to File -- " + "VTDL" + md5 + ".json"

  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

def main():
  opt=argparse.ArgumentParser(description="Search and Download from VirusTotal")
  opt.add_argument("HashorPath", help="Enter the MD5 Hash or Path to File")
  opt.add_argument("-s", "--search", action="store_true", help="Search VirusTotal")
  opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
  opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")
  opt.add_argument("-d", "--download", action="store_true", help="Download File from Virustotal (VTDLXXX.danger)")
  opt.add_argument("-p", "--pcap", action="store_true", help="Download Network Traffic (VTDLXXX.pcap)")
  opt.add_argument("-r", "--rescan",action="store_true", help="Force Rescan with Current A/V Definitions")
  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)
  options= opt.parse_args()
  vt=vtAPI()
  md5 = checkMD5(options.HashorPath)
  if options.search or options.jsondump or options.verbose:
    parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump)
  if options.download:
    name = "VTDL" + md5 + ".danger"
    vt.downloadFile(md5,name)
  if options.pcap:
    name = "VTDL" + md5 + ".pcap"
    vt.downloadPcap(md5,name)
  if options.rescan:
    vt.rescan(md5)

if __name__ == '__main__':
    main()
