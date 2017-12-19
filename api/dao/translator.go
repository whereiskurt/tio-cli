package dao

import (
 "log"
  "fmt"
  "time"
  "sort"
  "strings"
  "strconv"
  "sync"
  "tio-cli/api/tenable"
  "tio-cli/cmd/colour"
  "github.com/karlseguin/ccache"
)

const OUTPUT_WORKERS = 10

type TranslatorCollection struct {
  Translators *[]Translator
  Workers *sync.WaitGroup

  ScanIds []string
  Depth int
  PluginIds []string
  UniqueKey string

  Verbosity int
  IgnoreScan string
  IgnoreHistory string

  Portal *tenable.Portal
}

type Translator struct {
  Workers *sync.WaitGroup
  ThreadSafe *sync.Mutex
  ScanId string
  HistoryIndex int
  IncludePlugin string
  Portal *tenable.Portal
  IncludeHosts bool
  IncludeVulnerabilities bool
  
  Verbosity int
  IgnoreScan string
  IgnoreHistory string

}

type TranslatorHostRecord struct {
 translator *Translator
 
 raw *ScanHostPluginRecord 
 rawRollup *DaysVulnerableRecord

 rawScanDet *tenable.ScanDetails
 rawHostDet *tenable.HostDetails
}

type TranslatorScanRecord struct {
 Translator *Translator
 RawRecord * ScanDetailRecord

 RawScanDetails * tenable.ScanDetails
 RawScanItem *tenable.ScanListItem
}

func NewScanTranslator(scanId string, historyIndex int, includePlugin string, portal *tenable.Portal, verbosity int, ignoreHistory string) *Translator {
  r := new(Translator)

  r.Workers = new(sync.WaitGroup)
  r.ThreadSafe = new(sync.Mutex)
  r.ScanId = scanId
  r.HistoryIndex = historyIndex
  r.IncludePlugin = includePlugin
  r.Portal = portal
  r.Verbosity = verbosity
  r.IgnoreHistory = ignoreHistory
  return r
}


func NewTranslatorCollection(scanIds []string, depth int, pluginIds []string, uniqueKey string, portal *tenable.Portal, verbosity int, ignoreScans string) *TranslatorCollection {
  r := new(TranslatorCollection)
  r.Workers = new(sync.WaitGroup)
  r.ScanIds = scanIds
  r.Depth = depth
  r.PluginIds = pluginIds
  r.UniqueKey = uniqueKey
  r.Portal = portal
  r.Verbosity = verbosity
  r.IgnoreScan = ignoreScans

  return r
}

func (self *Translator) NewTranslatorHostRecord(tioScanDet *tenable.ScanDetails, tioHostDet *tenable.HostDetails, hostId string) *TranslatorHostRecord {
  rec := new(TranslatorHostRecord)

  rec.translator = self
  rec.raw = new(ScanHostPluginRecord)
  rec.rawRollup = new(DaysVulnerableRecord)
  rec.rawScanDet = tioScanDet
  rec.rawHostDet = tioHostDet

  rec.raw.HostId = hostId
  rec.raw.ScanId = self.ScanId
  rec.raw.HistoryIndex = string(self.HistoryIndex)

  return rec
}

func (record * ScanHostPluginRecord) NewDaysVulnerableRecord() * DaysVulnerableRecord {
  var r DaysVulnerableRecord

  r.ScanId = record.ScanId
  r.LastHistoryId = record.HistoryId
  r.LastHistoryIndex = record.HistoryIndex
  r.LastScanName = record.ScanName
  r.HostFQDN = record.HostFQDN
  r.HostIP = record.HostIP
  r.HostNetBIOS = record.HostNetBIOS
  r.HostOperatingSystems = record.HostOperatingSystems
  
  r.FirstScan = record.ScanEnd
  r.FirstScanUnix = record.ScanEndUnix

  r.FirstScan = record.ScanEnd
  r.FirstScanUnix = record.ScanEndUnix
  r.FirstPluginCriticalCount = record.PluginCriticalCount 
  r.FirstPluginHighCount = record.PluginHighCount
  r.FirstPluginMediumCount = record.PluginMediumCount
  r.FirstPluginLowCount = record.PluginLowCount
  r.FirstPluginTotalCount = record.PluginTotalCount
  
  r.LastScan = record.ScanEnd
  r.LastScanUnix = record.ScanEndUnix
  r.LastPluginCriticalCount = record.PluginCriticalCount 
  r.LastPluginHighCount = record.PluginHighCount
  r.LastPluginMediumCount = record.PluginMediumCount
  r.LastPluginLowCount = record.PluginLowCount
  r.LastPluginTotalCount = record.PluginTotalCount

  r.calculateDaysVulnerable()
  
  return &r
}

func (self *Translator) NewTranslatorScanRecord(tioScanItem *tenable.ScanListItem, tioScanDetails *tenable.ScanDetails, previous int, depth int, ignoreHistory string) *TranslatorScanRecord {
  var verbosity = self.Verbosity

  var ignore [] string  = strings.Split(ignoreHistory, ",")

  rec := new(TranslatorScanRecord)


  if verbosity > 0 {
    fmt.Println(colour.GREEN+fmt.Sprintf("    ->INFO: Collecting host details (scan_id: %v)", tioScanItem.Id)+colour.RESET)
  }


  rec.Translator = self

  rec.RawRecord = new(ScanDetailRecord)
  rec.RawScanDetails = tioScanDetails
  rec.RawScanItem = tioScanItem

  rec.RawRecord.ScanId = string(tioScanItem.Id)
  rec.RawRecord.Name = tioScanItem.Name

  rec.RawRecord.PolicyName = tioScanDetails.Info.PolicyName

  rec.RawRecord.CreationDate = string(tioScanItem.CreationDate)
  rec.RawRecord.LastModifiedDate = string(tioScanItem.LastModifiedDate)
  rec.RawRecord.Status  = tioScanItem.Status
  rec.RawRecord.Enabled  = fmt.Sprintf("%t",tioScanItem.Enabled)
  rec.RawRecord.RRules = tioScanItem.RRules
  rec.RawRecord.Timezone  = tioScanItem.Timezone
  rec.RawRecord.StartTime = tioScanItem.StartTime

  rec.RawRecord.TotalHistoryCount = fmt.Sprintf("%v", len(tioScanDetails.History))
  HistoricalScan:
  for i := previous; i < len(tioScanDetails.History) && i < depth + previous ; i++ {

    for _,skip := range ignore {
      if string(tioScanDetails.History[i].HistoryId) == skip {
        continue HistoricalScan
      }
    }

    var histDetails tenable.ScanDetails = self.Portal.GetScanDetails(rec.RawRecord.ScanId, i)

    hist := new(ScanDetailHistoryRecord)
    hist.HistoryId = fmt.Sprintf("%v", histDetails.History[i].HistoryId)
    hist.HostCount = fmt.Sprintf("%v", len(histDetails.Hosts))
    hist.LastModifiedDate  = string(histDetails.History[i].LastModifiedDate)
    hist.CreationDate  = string(histDetails.History[i].CreationDate)
    hist.Status = histDetails.History[i].Status
    if verbosity > 0 {
      fmt.Println(colour.GREEN+fmt.Sprintf("      ->INFO: %v hosts for scan_id: %v, history_id: %v ...", len(histDetails.Hosts), tioScanItem.Id,  hist.HistoryId)+colour.RESET)
    }

    for _, host := range histDetails.Hosts {
      
      self.ThreadSafe.Lock()
      critsHist, _ := strconv.Atoi(hist.PluginCriticalCount) 
      critsHost, _ := strconv.Atoi(string(host.SeverityCritical))
      hist.PluginCriticalCount =  fmt.Sprintf("%v", critsHist + critsHost)
      highHist, _ := strconv.Atoi(hist.PluginHighCount) 
      highHost, _ := strconv.Atoi(string(host.SeverityHigh))
      hist.PluginHighCount =  fmt.Sprintf("%v", highHist + highHost)
      mediumHist, _ := strconv.Atoi(hist.PluginMediumCount) 
      mediumHost, _ := strconv.Atoi(string(host.SeverityMedium))
      hist.PluginMediumCount =  fmt.Sprintf("%v", mediumHist + mediumHost)
      lowHist, _ := strconv.Atoi(hist.PluginLowCount) 
      lowHost, _ := strconv.Atoi(string(host.SeverityLow))
      hist.PluginLowCount =  fmt.Sprintf("%v", lowHist + lowHost)
      hist.PluginTotalCount =  fmt.Sprintf("%v", lowHist + lowHost + mediumHist + mediumHost + highHist + highHost + critsHist + critsHost)
      self.ThreadSafe.Unlock()

      if self.IncludeHosts == true {
        var hostId = string(host.Id)
        var hostDetails tenable.HostDetails = self.Portal.GetHostDetails(string(rec.RawRecord.ScanId), hostId, i)
        
        hostRec := self.NewTranslatorHostRecord(&histDetails, &hostDetails, hostId)

        hostRec.convertHostScanDetail(i) //O(1)
        hostRec.convertScanHostTimeDate() //O(1)
        hostRec.convertHostSeverityFromScan() //O(N) hosts       

        hist.Hosts = append(hist.Hosts, *hostRec.raw)  

      }
    }

    //First hosts are the most vulnerable (DESC)
    sort.Slice(hist.Hosts, func(i, j int) bool {
      var iv, jv int64
      iv, _ = strconv.ParseInt(string(hist.Hosts[i].PluginCriticalCount), 10, 64)
      jv, _ = strconv.ParseInt(string(hist.Hosts[j].PluginCriticalCount), 10, 64)

      if iv == jv { //If they are equal, HIGH
        iv, _ = strconv.ParseInt(string(hist.Hosts[i].PluginHighCount), 10, 64)
        jv, _ = strconv.ParseInt(string(hist.Hosts[j].PluginHighCount), 10, 64)  

        if iv == jv { //If they are equal, MED
          iv, _ = strconv.ParseInt(string(hist.Hosts[i].PluginMediumCount), 10, 64)
          jv, _ = strconv.ParseInt(string(hist.Hosts[j].PluginMediumCount), 10, 64)  

          if iv == jv { ////If they are equal, LOW
            iv, _ = strconv.ParseInt(string(hist.Hosts[i].PluginLowCount), 10, 64)
            jv, _ = strconv.ParseInt(string(hist.Hosts[j].PluginLowCount), 10, 64)  
          }
        } 
      }
      return iv > jv
    })
    if verbosity > 0 {
      fmt.Println(colour.GREEN+fmt.Sprintf("      ->INFO: Done. ")+colour.RESET)
    }

    if self.IncludeVulnerabilities == true {
      for _, vuln := range histDetails.Vulnerabilities {
        sev, _ := strconv.Atoi(string(vuln.Severity))
        if sev >= 0 { //sev=2(med),sev=3(high),sev=4(crit),
          plugin := self.NewHostPlugin(string(vuln.PluginId), vuln.Name, vuln.Family, string(vuln.Count), string(vuln.Severity))
          hist.Plugins = append(hist.Plugins, *plugin)
        }
      }
      //First items have the largest severity (DESC)
      sort.Slice(hist.Plugins, func(i, j int) bool {
        var iv, jv int64

        iv, _ = strconv.ParseInt(string(hist.Plugins[i].Severity), 10, 64)
        jv, _ = strconv.ParseInt(string(hist.Plugins[j].Severity), 10, 64)
        
        if iv == jv { //If they are equal, sort lexi by name (ASC)

          iv, _ = strconv.ParseInt(string(hist.Plugins[i].Count), 10, 64)
          jv, _ = strconv.ParseInt(string(hist.Plugins[j].Count), 10, 64)

          if iv == jv { //If they are equal, sort lexi by name (ASC)

            iv, _ = strconv.ParseInt(string(hist.Plugins[i].PluginId), 10, 64)
            jv, _ = strconv.ParseInt(string(hist.Plugins[j].PluginId), 10, 64)

          }
        }

        return iv > jv 
      })
    }

    rec.RawRecord.HistoryRecords = append(rec.RawRecord.HistoryRecords, *hist)
  }
  if verbosity > 0 {
    fmt.Println(colour.GREEN+fmt.Sprintf("    ->INFO: Done collecting scan host details (scan_id: %v)", tioScanItem.Id)+colour.RESET)
  }

  return rec
}

var ANY_PLUGIN string = ""
func (self *TranslatorCollection) TranslateToScanDetailRows(out chan ScanDetailRecord, includeHosts bool, includeVulnerabilities bool, previous string, verbosity int, ignoreHistory string) {

  var scanItemMap = make(map[string] tenable.ScanListItem)
  var scanList = self.Portal.GetScanList()
  for _, scan := range scanList.Scans {
    scanItemMap[string(scan.Id)] = scan
  }

  ScanList:
  for _, scanId := range self.ScanIds {
    if verbosity > 0 {
      fmt.Println(colour.GREEN+fmt.Sprintf("->INFO: Collecting scan details for scan_id: %v ...", scanId)+colour.RESET)
    }

    for _, skip := range strings.Split(self.IgnoreScan, ",") {
      if string(scanId) == skip { 
        fmt.Println(colour.GREEN+fmt.Sprintf("->INFO: Skipping scan_id: %v ...", scanId)+colour.RESET)
        continue ScanList
      }
    }


    var prev, _ = strconv.ParseInt(previous, 10, 32)
    var translator = NewScanTranslator(scanId, int(prev), ANY_PLUGIN, self.Portal, verbosity, ignoreHistory)
    
    translator.IncludeHosts = includeHosts
    translator.IncludeVulnerabilities = includeVulnerabilities

    var records = make(chan TranslatorScanRecord) 
    go translator.translateScanDetail(records, scanItemMap, previous, self.Depth, ignoreHistory)
    for record := range records {
      out <- *record.RawRecord
    }

    if verbosity > 0 {
      fmt.Println(colour.GREEN+fmt.Sprintf("->INFO: Done collecting scan details for scan_id: %v ", scanId)+colour.RESET)
    }
  }


  close(out)

  return
}
//Slow
func (self *Translator) translateScanDetail(out chan TranslatorScanRecord, scanItemMap map[string] tenable.ScanListItem, previous string, depth int, ignoreHistory string) {

  var prev, _ = strconv.ParseInt(previous, 10, 32)
  var prev32 int = int(prev) //this is as per the manual

  var item tenable.ScanListItem = scanItemMap[self.ScanId]
  var currentDetails tenable.ScanDetails = self.Portal.GetScanDetails(self.ScanId, prev32)

  var rec = self.NewTranslatorScanRecord(&item, &currentDetails, prev32, depth, ignoreHistory)
  
  out <- *rec

  close(out)
  return
}

func (self *TranslatorCollection) TranslateToDaysVulnerableRows(out chan DaysVulnerableRecord) {
  var rollupMap = make(map[string] DaysVulnerableRecord)
  
  for _, pluginId := range self.PluginIds {
    for _, scanId := range self.ScanIds {     
      for historyIndex := 0; historyIndex <= self.Depth; historyIndex++ {

        var records = make(chan TranslatorHostRecord)
        var translator = NewScanTranslator(scanId, historyIndex, pluginId, self.Portal, self.Verbosity, self.IgnoreHistory)
        
        go translator.translateHost(records)

        for record := range records {
          //#1. Filter records that don't match 
          if record.raw.HostPluginsMatchCount == "0" {continue}

          var key = record.raw.HostIP
          if self.UniqueKey == "HostFQDN" { //Override and us FQDN
            key = record.raw.HostFQDN
          } 
          if key == "" {continue}

          record.rawRollup = record.raw.NewDaysVulnerableRecord()

           //#3. Lookup the record based on the 'key'
          var rollupRecord, found = rollupMap[key]

          if !found {
            rollupRecord = *record.rawRollup
          } else {           
            //#3b) Found in a past historical scan, so the first detect is even older!
            rollupRecord.UpdateFirstScan(record)
          }

          rollupMap[key] = rollupRecord
        }
      }
    }
  }

  for _, record := range rollupMap { 
    out <- record
  }

  close(out)

  return
}


//Fast!
func (self *Translator) TranslateToScanHostRows(out chan ScanHostPluginRecord) {
  var records = make(chan TranslatorHostRecord)
  
  go self.translateHost(records)

  for record := range records {
    out <- *record.raw
  }
  close(out)

  return
}

func (self *Translator) translateHost(out chan TranslatorHostRecord) {

  var scan = self.Portal.GetScanDetails(self.ScanId, self.HistoryIndex)

  for _, skip := range strings.Split(self.IgnoreHistory, ",") {
    if string(scan.History[self.HistoryIndex].HistoryId) == skip { 
      close(out)
      return
    }
  }

  var chanHosts = make(chan string, 2 * OUTPUT_WORKERS)

  for i := 0; i < OUTPUT_WORKERS; i++ {
    self.Workers.Add(1)
    go self.consumeHost(&scan, chanHosts, out)
  }
  
  self.produceHost(&scan, chanHosts)
  
  self.Workers.Wait()

  close(out)
  return 
}

func (self *Translator) produceHost(scan *tenable.ScanDetails, chanHosts chan string) {
  for _, scannedHost := range scan.Hosts {
    var hostId = string(scannedHost.Id)
    chanHosts <- hostId
  }
  close(chanHosts)
}

func (self *Translator) consumeHost(scan *tenable.ScanDetails, hostsChannel chan string, outRecordsChannel chan TranslatorHostRecord) {

  for hostId := range hostsChannel {

    var host tenable.HostDetails = self.Portal.GetHostDetails(self.ScanId, hostId, self.HistoryIndex)

    r := self.NewTranslatorHostRecord(scan, &host, hostId)


    r.convertHostScanDetail(self.HistoryIndex) //O(1)
    r.convertScanHostTimeDate() //O(1)
    r.convertHostSeverityFromScan() //O(N) hosts       
    r.convertHostPlugins() //O(N^2) vulnerability x vuln.attribute

    r.calcCSVPluginCountRow()

    outRecordsChannel <- *r
  }

  self.Workers.Done()

  return
}

func (record * TranslatorHostRecord) convertHostScanDetail(historyIndex int) {
  var scanId = record.translator.ScanId
  var scanDetails *tenable.ScanDetails  = record.rawScanDet
  var hostDetails *tenable.HostDetails = record.rawHostDet
  var historyId = scanDetails.History[historyIndex].HistoryId

  var scanName = record.translator.Portal.GetScanName(scanId)

  var hostIP = hostDetails.Info.HostIP
  var fqdn = hostDetails.Info.FQDN
  var netbios = hostDetails.Info.NetBIOS
  var mac = hostDetails.Info.MACAddress
  var os = hostDetails.Info.OperatingSystem
  
  var scannerName = scanDetails.Info.ScannerName
  var scanPolicyName = scanDetails.Info.PolicyName

  mac = strings.Replace(mac,"\n", "|", -1)
  os  = strings.Replace(os, "\n", "|", -1)

  //Simplify OS names
  os = strings.Replace(os,"Microsoft Windows 10"            ,"Win10", -1)
  os = strings.Replace(os,"Microsoft Windows 7"             ,"Win7", -1)
  os = strings.Replace(os,"Microsoft Windows XP"            ,"XP", -1)
  os = strings.Replace(os,"Microsoft Windows Vista"         ,"Vista", -1)
  os = strings.Replace(os,"Windows XP "                     ,"XP", -1)
  os = strings.Replace(os,"Microsoft Windows 2000 Server"   ,"Win2K", -1)
  os = strings.Replace(os,"Microsoft Windows Server 2003"   ,"Win2003", -1)
  os = strings.Replace(os,"Microsoft Windows Server 2008"   ,"Win2008", -1)
  os = strings.Replace(os,"Microsoft Windows Server 2012"   ,"Win2012", -1)
  os = strings.Replace(os,"Windows Server 2016"             ,"Win2016", -1)
  os = strings.Replace(os,"Microsoft Windows NT 4.0 Server" ,"WinNT4", -1)
  os = strings.Replace(os,"Microsoft Windows NT 4.0"        ,"WinNT4", -1)

  os = strings.Replace(os,"Standard" ,"", -1)
  os = strings.Replace(os,"Enterprise" ,"", -1)
  os = strings.Replace(os,"for Embedded Systems" ,"", -1)
  

  os = strings.Replace(os," Service Pack "            ,"SP", -1)
  os = strings.Replace(os," Service Pack 1"            ,"SP1", -1)
  os = strings.Replace(os," Service Pack 2"            ,"SP2", -1)
  
  os = strings.Replace(os,"Linux Kernel"            ,"Linux", -1)
  os = strings.Replace(os,"Dell Remote Access Controller"            ,"DRAC", -1)

  os = strings.Replace(os,"XP|XP"                     ,"XP", -1)

  if os == "" {
    os = "Not Detected"
  }
  record.raw.HistoryId = string(historyId)
  record.raw.HistoryIndex = string(historyIndex)
  record.raw.ScanName = scanName
  record.raw.HostIP = hostIP
  record.raw.HostFQDN = fqdn
  record.raw.HostNetBIOS = netbios
  record.raw.HostMACAddresses = mac
  record.raw.HostOperatingSystems = os
  record.raw.HostScannerName = scannerName
  record.raw.ScanPolicyName = scanPolicyName

  return
}

func (record * TranslatorHostRecord) convertScanHostTimeDate() {
  var hostDetails *tenable.HostDetails = record.rawHostDet

  var tzLookupForScanner = record.translator.Portal.GetTimezone(record.raw.HostScannerName)

  
  rawHostStart, err := time.Parse(time.ANSIC, hostDetails.Info.HostStart)
  if err != nil {
    //log.Fatal(fmt.Sprintf("time.Parse HostStart failed: '%v' to parse record scanId %s for hostId %s\n", hostDetails.Info.HostStart, record.raw.ScanId, record.raw.HostId ))
  }

  //Normalize DTS - scanners report in their localtime w/out TZ!
  var hostStartScannerTZ = strings.Replace(fmt.Sprintf("%v", rawHostStart), "+0000 UTC", tzLookupForScanner, -1)
  tmHostScanStartTZ, errTZ := time.Parse(tenable.TZ_FORMAT, hostStartScannerTZ)
  if errTZ != nil {
    //log.Fatal(fmt.Sprint("KPHKPHKPH: TZ parsing error."))
  }

  rawHostEnd, err2 := time.Parse(time.ANSIC, hostDetails.Info.HostEnd)
  if err2 != nil {
    //log.Fatal(fmt.Sprint("time.Parse HostEnd failed: '%v' scanId %s for hostId %s\n", hostDetails.Info.HostEnd, record.raw.ScanId, record.raw.HostId ))
  }

  //Normalize DTS - scanners report in their localtime w/out TZ!
  var hostEndScannerTZ = strings.Replace(fmt.Sprintf("%v", rawHostEnd), "+0000 UTC", tzLookupForScanner, -1)
  tmHostScanEndTZ, errTZ2 := time.Parse(tenable.TZ_FORMAT, hostEndScannerTZ)

  if errTZ2 != nil {
    //log.Fatal(fmt.Sprint("Timezone Error for hostEndScannerTZ"))
  }



  var hostScanStart = fmt.Sprintf("%v", tmHostScanStartTZ.In(time.Local))
  var hostScanStartUnix = fmt.Sprintf("%v", tmHostScanStartTZ.In(time.Local).Unix())
  var hostScanEnd = fmt.Sprintf("%v", tmHostScanEndTZ.In(time.Local))
  var hostScanEndUnix = fmt.Sprintf("%v", tmHostScanEndTZ.In(time.Local).Unix())
  var hostScanDuration = fmt.Sprintf("%v", rawHostEnd.Sub(rawHostStart))

  rawScanStart, errParseStart := strconv.ParseInt(string(record.rawScanDet.Info.Start), 10, 64)
  if errParseStart != nil {
      rawScanStart =  int64(0) //OMG! BAD DATA! ... set a default.
      log.Fatal(fmt.Sprint("Timezone Error for hostStartScannerTZ"))
  }

  rawScanEnd, errParseEnd := strconv.ParseInt(string(record.rawScanDet.Info.End), 10, 64)
  if errParseEnd != nil {
    rawScanEnd =  rawScanStart //OMG! BAD DATA! ... likely aborted scan.
  }

  unixScanStart := time.Unix(rawScanStart, 0)
  unixScanEnd := time.Unix(rawScanEnd, 0)
  var scanStart = fmt.Sprintf("%v", unixScanStart)
  var scanStartUnix = fmt.Sprintf("%s", string(record.rawScanDet.Info.Start))
  var scanEnd = fmt.Sprintf("%v", unixScanEnd)
  var scanEndUnix = fmt.Sprintf("%s", string(record.rawScanDet.Info.End))
  var scanDuration = fmt.Sprintf("%v", unixScanEnd.Sub(unixScanStart))

  record.raw.ScanStart = scanStart
  record.raw.ScanStartUnix = scanStartUnix
  record.raw.ScanEnd = scanEnd
  record.raw.ScanEndUnix = scanEndUnix
  record.raw.ScanDuration = scanDuration

  record.raw.HostScanStart = hostScanStart
  record.raw.HostScanStartUnix = hostScanStartUnix
  record.raw.HostScanEnd = hostScanEnd
  record.raw.HostScanEndUnix = hostScanEndUnix
  record.raw.HostScanDuration = hostScanDuration

  return
}

func (record * TranslatorHostRecord) convertHostSeverityFromScan() {
  var scanDetails *tenable.ScanDetails = record.rawScanDet

  //For the Host lookup counts for CRIT/HIGH/MED/LOW...
  var matchedAHost bool = false

  for _, host := range scanDetails.Hosts {
    if string(host.Id) == record.raw.HostId {
      record.raw.PluginCriticalCount = string(host.SeverityCritical)
      record.raw.PluginHighCount = string(host.SeverityHigh)
      record.raw.PluginMediumCount = string(host.SeverityMedium)
      record.raw.PluginLowCount = string(host.SeverityLow)
      record.raw.PluginTotalCount = string(host.SeverityTotal)

      matchedAHost = true
      break;
    }
  }

  if matchedAHost == false {
    panic(fmt.Sprintf(`Local cache is out of sync: 
        ScandId:%s, HostId:%s, HostIP:%s
      `, record.raw.ScanId, record.raw.HostId, record.raw.HostIP))
  }

  return
}


func (record * TranslatorHostRecord) convertHostPlugins() {
  var hostDetails *tenable.HostDetails = record.rawHostDet

  for _, vuln := range hostDetails.Vulnerabilities {

    plugin := record.translator.NewHostPlugin(string(vuln.PluginId), vuln.PluginName, vuln.PluginFamily, string(vuln.Count), string(vuln.Severity))

    record.raw.HostPlugins = append(record.raw.HostPlugins, *plugin)
  }

  return;
}

func (record * TranslatorHostRecord) calcCSVPluginCountRow() {
  var includePlugin string = record.translator.IncludePlugin
  var row[] string
  var neededAtLeastOneMatch bool = includePlugin != "" //IF '--plugins' then only include hosts that match
  var totalPluginMatches int = 0

  for _, searchPluginId := range strings.Split(includePlugin, ",") {
    var hadAtLeastOnePluginMatch bool = false
    
    for _, hostPlugin := range record.raw.HostPlugins {
      if searchPluginId == hostPlugin.PluginId {
        hadAtLeastOnePluginMatch = true 
        totalPluginMatches = totalPluginMatches + 1
        row = append(row, hostPlugin.Count)  
        break
      }
    }

    if ! hadAtLeastOnePluginMatch && neededAtLeastOneMatch {
      row = append(row, "0")    
    }
  }

 	record.raw.HostPluginsMatchCSVCount = fmt.Sprintf("%s", strings.Join(row,","))
	record.raw.HostPluginsMatchCount = fmt.Sprintf("%d", totalPluginMatches)

  return
}


func (record * DaysVulnerableRecord) UpdateFirstScan(from TranslatorHostRecord) {

  record.FirstScan = from.rawRollup.FirstScan
  record.FirstScanUnix = from.rawRollup.FirstScanUnix

  record.FirstPluginCriticalCount = from.raw.PluginCriticalCount
  record.FirstPluginHighCount = from.raw.PluginHighCount
  record.FirstPluginMediumCount = from.raw.PluginMediumCount
  record.FirstPluginLowCount = from.raw.PluginLowCount
  record.FirstPluginTotalCount = from.raw.PluginTotalCount

  record.calculateDaysVulnerable()

  return
}

func (record *DaysVulnerableRecord) calculateDaysVulnerable() {
 //Calculate DaysSince...
  rawFirstScan, errParseStart := strconv.ParseInt(string(record.FirstScanUnix), 10, 64)
  if errParseStart != nil {
      rawFirstScan =  int64(0) 
  }
  unixFirstStart := time.Unix(rawFirstScan, 0)

  rawLastScan, errParseStart := strconv.ParseInt(string(record.LastScanUnix), 10, 64)
  if errParseStart != nil {
      rawLastScan =  int64(0)
  }
  unixLastStart := time.Unix(rawLastScan, 0)

  dFirst := time.Now().Sub( unixFirstStart )
  dLast := time.Now().Sub( unixLastStart )

  record.DaysSinceFirstDetection = fmt.Sprintf("%.0f", dFirst.Hours() / 24)
  record.DaysSinceLastDetection = fmt.Sprintf("%.0f", dLast.Hours() / 24)

  var sd tenable.ScanDetails = tenable.NewPortal().GetScanDetails(record.ScanId, 0)

  //Calculate daysSinceLastScanRun
  rawScanStart, errParseStart := strconv.ParseInt(string(sd.Info.End), 10, 64)
  if errParseStart != nil {
      rawScanStart =  int64(0) //OMG! BAD DATA! ... set a default
  }
  unixLastScanRun := time.Unix(rawScanStart, 0)
  dLastScanRun := time.Now().Sub( unixLastScanRun )
  
  record.LastScanRun = fmt.Sprintf("%v", unixLastScanRun)
  record.DaysSinceLastScanRun = fmt.Sprintf("%.0f", dLastScanRun.Hours() / 24)

  if record.DaysSinceLastScanRun == record.DaysSinceLastDetection {
    record.VulnerableStatus = "Vulnerable"
    record.DurationStatus = fmt.Sprintf("%s days", record.DaysSinceFirstDetection)
    record.IsVulnerable = true
  } else {
    record.VulnerableStatus = "Patched"
    record.DurationStatus = fmt.Sprintf("-%s days", record.DaysSinceLastDetection)
    record.IsPatched = true
  }

  return
}


var memcache = ccache.New(ccache.Configure().MaxSize(500000).ItemsToPrune(500))

func (self * Translator) NewHostPlugin(pluginId string, pluginName string, pluginFamily string, count string, sev string ) * HostPlugin {
  var key string = "plugin:" + pluginId
  var plugin = new(HostPlugin)

  item  := memcache.Get(key)
  if item  != nil {
    plugin  = item.Value().(*HostPlugin)   

  } else {
    plugin.PluginId = pluginId
    plugin.Name = pluginName
    plugin.Family = pluginFamily
    plugin.Severity = sev
    
    var pluginDetail tenable.Plugin = self.Portal.GetPlugin(plugin.PluginId)


    plugin.RiskFactor = pluginDetail.RiskFactor
    plugin.FunctionName = pluginDetail.FunctionName
    plugin.PluginPublicationDate = pluginDetail.PluginPublicationDate
    plugin.PatchPublicationDate = pluginDetail.PatchPublicationDate

    for _, a := range pluginDetail.Attributes {
      var destA HostPluginAttribute
      destA.Name = a.Name
      destA.Value = a.Value
      plugin.Attributes = append(plugin.Attributes, destA)
    }
    memcache.Set(key, plugin, time.Minute * 60)
  }

  plugin.Count = count

  return plugin
}
