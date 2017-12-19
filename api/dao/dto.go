package dao

type DaysVulnerableRecord struct {
  ScanId string `json:"ScanId"`
  LastHistoryId string `json:"lastHistoryId"`
  LastHistoryIndex string `json:"lastHistoryIndex"`
  LastScanName  string `json:"lastScanName"`

  LastScan string `json:"lastScan"`
  LastScanUnix string `json:"lastScanUnix"`
  LastPluginCriticalCount string `json:"lastPluginCriticalCount"`
  LastPluginHighCount string `json:"lastPluginHighCount"`
  LastPluginMediumCount string `json:"lastPluginMediumCount"`
  LastPluginLowCount string `json:"lastPluginLowCount"`
	LastPluginTotalCount string `json:"lastPluginTotalCount"`

  HostIP  string `json:"hostIP"`
  HostFQDN  string `json:"hostFQDN"`
  HostNetBIOS  string `json:"hostNetBIOS"`
  HostMACAddresses string `json:"hostMACAddresses"`	
	HostOperatingSystems string `json:"hostOperatingSystems"`

	Plugin HostPlugin `json:"plugin"`

	FirstScan string `json:"firstScan"`
  FirstScanUnix string `json:"firstScanUnix"`
  FirstPluginCriticalCount string `json:"firstPluginCriticalCount"`
  FirstPluginHighCount string `json:"firstPluginHighCount"`
  FirstPluginMediumCount string `json:"firstPluginMediumCount"`
  FirstPluginLowCount string `json:"firstPluginLowCount"`
	FirstPluginTotalCount string `json:"firstPluginTotalCount"`
  
  DaysSinceFirstDetection string `json:"daysSinceFirstDetection"`
  DaysSinceLastDetection string `json:"DaysSinceLastDetection"`
  DaysSinceLastScanRun string `json:"DaysSinceLastScanRun"`
  
  LastScanRun string `json:"LastScanRun"`

  VulnerableStatus string `json:"VulnerableStatus"`
  DurationStatus string `json:"DurationStatus"`
  IsVulnerable bool `json:"IsVulnerable"`
  IsPatched bool `json:"IsPatched"`
}

type ScanHostPluginRecord struct {
  ScanId string `json:"scanId"`
  HostId  string `json:"hostId"`
  HistoryId string `json:"historyId"`
  HistoryIndex string `json:"historyIndex"`

  ScanName  string `json:"scanName"`
  ScanPolicyName  string `json:"scanPolicyName"`

  ScanStart string `json:"scanStart"`
  ScanStartUnix string `json:"scanStartUnix"`
  ScanEnd string `json:"scanEnd"`
  ScanEndUnix string `json:"scanEndUnix"`
  ScanDuration string `json:"scanDuration"`

  HostFQDN  string `json:"hostFQDN"`
  HostIP  string `json:"hostIP"`
  HostScannerName  string `json:"hostScannerName"`

	HostScanStart string `json:"hostScanStart"`
  HostScanStartUnix string `json:"hostScanStartUnix"`
  HostScanEnd string `json:"hostScanEnd"`
  HostScanEndUnix string `json:"hostScanEndUnix"`
  HostScanDuration string `json:"hostScanDuration"`

	HostNetBIOS string `json:"hostNetBIOS"` //Windows only, but prevelant.

  HostMACAddresses string `json:"hostMACAddresses"`	
	HostOperatingSystems string `json:"hostOperatingSystems"`

 	HostPlugins[] HostPlugin `json:"hostPlugins"`
 	HostPluginsMatchCSVCount string `json:"hostPluginsCSV"`
	HostPluginsMatchCount string `json:"hostPluginsMatchCount"`

  PluginCriticalCount string `json:"pluginCriticalCount"`
  PluginHighCount string `json:"pluginHighCount"`
  PluginMediumCount string `json:"pluginMediumCount"`
  PluginLowCount string `json:"pluginLowCount"`
	PluginTotalCount string `json:"pluginTotalCount"`
}

type HostPlugin struct {
	PluginId string `"json:pluginId"`
	Name string `"json:pluginName"`
	Family string `"json:pluginFamily"`
	Count string `"json:pluginCount"`
	Severity string `"json:severityTypeId"`

  RiskFactor string `"json:riskFactor"`
  FunctionName string `"json:functionName"`
  PluginPublicationDate string `"json:pluginPublicationDate"`
  PatchPublicationDate string `"json:patchPublicationDate"`

  Attributes[] HostPluginAttribute 
}
type HostPluginAttribute struct {
  Name  string `json:"name"`
  Value string `json:"value"`
}

type ScanDetailRecord struct {
  ScanId string `json:"scanId"`
  Name string `json:"name"`
  Status  string `json:"status"`

  PolicyName string `json:"policyName"`
  CreationDate string `json:'creationDate'`
  LastModifiedDate string `json:'lastModifiedDate'`

  Enabled  string `json:"enabled"`
  RRules  string `json:"rrules"`
  Timezone  string `json:"timezone"`
  StartTime  string `json:"startTime"`

  TotalHistoryCount string `json:'totalHistoryCount'`
  
  HistoryRecords[] ScanDetailHistoryRecord  
}
type ScanDetailHistoryRecord struct {
  HistoryId string `json:"historyId"`
  Status  string `json:"status"`
  CreationDate string `json:'createDate'`
  LastModifiedDate string `json:'lastModifiedDate'`
  
  Plugins[] HostPlugin `json:"plguins"`
  PluginCriticalCount string `json:"pluginCriticalCount"`
  PluginHighCount string `json:"pluginHighCount"`
  PluginMediumCount string `json:"pluginMediumCount"`
  PluginLowCount string `json:"pluginLowCount"`
  PluginTotalCount string `json:"pluginTotalCount"`

  HostCount string `json:"hostCount"`
  Hosts[] ScanHostPluginRecord `json:"hosts"`
}

