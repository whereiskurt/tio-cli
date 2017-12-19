package dao

import (
  "tio-cli/api/tenable"
  "strings"
  "fmt"
)

var scanHostPluginRecordHeaderTitle = []string{"ScanID", "HistoryId", "HostId", "ScanName", "ScanStart", "ScanStartUnix","ScanEnd", "ScanEndUnix", "ScanDuration", "HostScanStart","HostScanStartUnix","HostScanEnd","HostScanEndUnix", "HostScanDuration", "HostIP", "MACAddress", "HostName", "NetBIOS", "OperatingSystem", "Critical", "High", "Medium", "Low"}

func ToCSVHostHeader(includePlugins string, portal *tenable.Portal) [] string {
  headerTitle := scanHostPluginRecordHeaderTitle

  if includePlugins != "" {  
    var pluginHeaderTitle = ToCSVPluginHeader(includePlugins, portal)

    if len(pluginHeaderTitle) > 0 {
      headerTitle = append(headerTitle, pluginHeaderTitle ... )
    }
  }

  return headerTitle
}

func ToCSVPluginHeader(includePlugins string, portal *tenable.Portal) []string {
  var pluginHeaderTitle [] string
  
  for _, pluginId := range strings.Split(includePlugins, ",") {
    var pluginDetail tenable.Plugin = portal.GetPlugin(pluginId)

    //TODO: Add a mature CSV plugin to handle all edge cases etc. .. GTBABW
    //Comma Safe, QuoteSafe? Plugin Name! :-)
    var pluginName = pluginDetail.Name
        pluginName = strings.Replace(pluginName, `,`, ` `, -1)
        pluginName = strings.Replace(pluginName, `"`, `'`, -1)
    
    pluginHeaderTitle = append(pluginHeaderTitle, fmt.Sprintf("\"%s (%s)\"",pluginName, pluginId))
  }
  
  return pluginHeaderTitle
}

func (record * ScanHostPluginRecord) ToCSV() string {
  //TODO: Replace with CSV templates and proper output.
  var rowCSV = []string{record.ScanId, record.HistoryId, record.HostId, `"` + record.ScanName + `"`, record.ScanStart, record.ScanStartUnix, record.ScanEnd, record.ScanEndUnix, record.ScanDuration, record.HostScanStart, record.HostScanStartUnix, record.HostScanEnd, record.HostScanEndUnix, record.HostScanDuration, record.HostIP, record.HostMACAddresses, record.HostFQDN, record.HostNetBIOS,  `"` + record.HostOperatingSystems + `"`, record.PluginCriticalCount, record.PluginHighCount, record.PluginMediumCount, record.PluginLowCount }    
  if record.HostPluginsMatchCSVCount != "" {
    rowCSV = append(rowCSV, record.HostPluginsMatchCSVCount)
  }
  return fmt.Sprintf("%s", strings.Join(rowCSV,","))
}


var DaysVulnerableRecordHeaderTitle = []string{"ScanId","ScanName","LastRun","DaysSinceLastRun","LastDetect","DaysSinceLastDetect","FirstDetect","DaysSinceFirstDect","HostIP","HostFQDN","HostNetBIOS","HostOperatingSystems","PluginId","VulnerableStatus","DurationStatus","Critical","High","Medium","Low"}

func (record * DaysVulnerableRecord) ToCSV(pluginId string) string {
  var rowCSV = []string{record.ScanId, record.LastScanName, record.LastScanRun[0:10], record.DaysSinceLastScanRun, record.LastScan[0:10], record.DaysSinceLastDetection, record.FirstScan[0:10], record.DaysSinceFirstDetection, record.HostIP, record.HostFQDN, record.HostNetBIOS, record.HostOperatingSystems, pluginId, record.VulnerableStatus, record.DurationStatus, record.LastPluginCriticalCount, record.LastPluginHighCount, record.LastPluginMediumCount, record.LastPluginLowCount}
  return fmt.Sprintf("%s", strings.Join(rowCSV,","))
}