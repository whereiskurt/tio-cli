package dao

import (
	"fmt"
	"strconv"
  "strings"
	"sort"
	"time"
)

var TM_FORMAT_NOTZ = "Mon Jan _2 15:04:05 2006"
var TM_FORMAT_TZ string = "2006-01-_2 15:04:05 -0700 MST"

func (trans *Translator) FromNoTZ(dts string, setTZ string) (withTZ string, unix time.Time, err error) {

  dtsInt, err := strconv.ParseInt(dts, 10, 64)
  if err == nil {
    unix = time.Unix(dtsInt, 0)
  } else {
    unix, err = time.Parse(TM_FORMAT_NOTZ, dts)
    if err != nil {
      trans.Warnf("Couldn't parse time.ANSIC for '%v' as integer.", dts)    
      return withTZ, unix, err
    }
  }

  //Render UNIX time (which is UTC 0) and add timezone from scanner.
  //The scanner captured the UNIX time, without a TZ.
  withTZ = strings.Replace(fmt.Sprintf("%v", unix), "+0000 UTC", setTZ, -1)
  tmTZ, err := time.Parse(TM_FORMAT_TZ, withTZ)

  if err != nil {
    trans.Warnf("Couldn't parse Unix date '%v' with timezone '%s'.", unix, setTZ)
    return withTZ, unix, err
  }
  withTZ = fmt.Sprintf("%v", tmTZ)
  return withTZ, unix, err
}

func (trans *Translator) SortScanPluginKeys(rec * ScanHistoryDetail) (pluginKeys []string) {
  for k := range rec.HostPlugin {
    pluginKeys = append(pluginKeys, k)
  }

  sort.Slice(pluginKeys, func(i, j int) bool {
    var iv, jv int64

    ikey := pluginKeys[i]
    jkey := pluginKeys[j]

    iv, _ = strconv.ParseInt(string(rec.HostPlugin[ikey].Severity), 10, 64)
    jv, _ = strconv.ParseInt(string(rec.HostPlugin[jkey].Severity), 10, 64)
    
    if iv == jv { //If they are equal, sort lexi by name (ASC)

      iv, _ = strconv.ParseInt(string(rec.HostPlugin[ikey].Count), 10, 64)
      jv, _ = strconv.ParseInt(string(rec.HostPlugin[jkey].Count), 10, 64)

      if iv == jv { //If they are equal, sort lexi by name (ASC)

        iv, _ = strconv.ParseInt(string(rec.HostPlugin[ikey].PluginId), 10, 64)
        jv, _ = strconv.ParseInt(string(rec.HostPlugin[jkey].PluginId), 10, 64)

      }
    }

    return iv > jv 
  })


  return pluginKeys
}

func (trans *Translator) SortScanHostKeys(rec * ScanHistoryDetail) (hostKeys []string) {
  for k := range rec.Host {
    hostKeys = append(hostKeys, k)
  }

  sort.Slice(hostKeys, func(i, j int) bool {
    var iv, jv int64
    ikey := hostKeys[i]
    jkey := hostKeys[j]

    iv, _ = strconv.ParseInt(string(rec.Host[ikey].PluginCriticalCount), 10, 64)
    jv, _ = strconv.ParseInt(string(rec.Host[jkey].PluginCriticalCount), 10, 64)

    if iv == jv { //If they are equal, HIGH
      iv, _ = strconv.ParseInt(string(rec.Host[ikey].PluginHighCount), 10, 64)
      jv, _ = strconv.ParseInt(string(rec.Host[jkey].PluginHighCount), 10, 64)  

      if iv == jv { //If they are equal, MED
        iv, _ = strconv.ParseInt(string(rec.Host[ikey].PluginMediumCount), 10, 64)
        jv, _ = strconv.ParseInt(string(rec.Host[jkey].PluginMediumCount), 10, 64)  

        if iv == jv { ////If they are equal, LOW
          iv, _ = strconv.ParseInt(string(rec.Host[ikey].PluginLowCount), 10, 64)
          jv, _ = strconv.ParseInt(string(rec.Host[jkey].PluginLowCount), 10, 64)  
        }
      } 
    }
    return iv > jv
  })
  return hostKeys
}

func (trans *Translator) ShouldSkipScanId(scanId string) (skip bool) {
  skip = false

  if trans.Anonymizer != nil {
    scanId = trans.Anonymizer.DeAnonScanId(scanId)
  }

  _, ignore := trans.IgnoreScanId[scanId]
  if ignore {
    skip = true
  }

  if len(trans.IncludeScanId) > 0 {
    _, include := trans.IncludeScanId[scanId]
    if !include {
      skip = true
    }
  }
  return skip
}

func (trans *Translator) ShouldSkipAssetId(AssetId string) (skip bool) {
  skip = false

  _, ignore := trans.IgnoreAssetId[AssetId]
  if ignore {
    skip = true
  }

  if len(trans.IncludeAssetId) > 0 {
    _, include := trans.IncludeAssetId[AssetId]
    if !include {
      skip = true
    }
  }
  return skip
}

func (trans *Translator) ShouldSkipPluginId(pluginId string) (skip bool) {
  skip = false

  _, ignore := trans.IgnorePluginId[pluginId]
  if ignore {
    skip = true
  }

  if len(trans.IncludePluginId) > 0 {
    _, include := trans.IncludePluginId[pluginId]
    if !include {
      skip = true
    }
  }
  return skip
}

func (trans *Translator) ShouldSkipHistoryId(historyId string) (skip bool) {
  skip = false

  _, ignore := trans.IgnoreHistoryId[historyId]
  if ignore {
    skip = true
  }

  if len(trans.IgnoreHistoryId) > 0 {
    _, include := trans.IgnoreHistoryId[historyId]
    if !include {
      skip = true
    }
  }
  return skip
}