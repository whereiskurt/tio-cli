package dao

type Scan struct {
	ScanId      string `json:"id"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Owner       string `json:"owner"`
	Targets     string `json:"targets"`
	ScannerName string `json:"scanner_name"`

	UserPermissions  string `json:"user_permissions"`
	Enabled          string `json:"enabled"`
	RRules           string `json:"rrules"`
	Timezone         string `json:"timezone"`
	StartTime        string `json:"startTime"`
	CreationDate     string `json:"creation_date"`
	LastModifiedDate string `json:"last_modification_date"`
	PolicyName       string `json:"policy_name"`
	Timestamp        string `json:"timestamp"`
}

type ScanHistory struct {
	Scan               Scan
	ScanHistoryCount   string `json:'ScanHistoryCount'`
	ScanHistoryDetails []ScanHistoryDetail
}

type HostPluginExposure struct {
  Host HostScanSummary
  Plugin PluginDetailSummary
  FirstScan ScanHistoryDetail
  LastScan ScanHistoryDetail
  DaysSinceFirstDetection string `json:"daysSinceFirstDetection"`
  DaysSinceLastDetection string `json:"DaysSinceLastDetection"`
  VulnerableStatus string `json:"VulnerableStatus"`
  DurationStatus string `json:"DurationStatus"`
  IsVulnerable bool `json:"IsVulnerable"`
  IsPatched bool `json:"IsPatched"`
}

type ScanHistoryDetail struct {
	Scan Scan

	HistoryId           string `json:"historyId"`
	HistoryIndex        string `json:"historyIndex"`
	Status              string `json:"status"`
	CreationDate        string `json:'createDate'`
	LastModifiedDate    string `json:'lastModifiedDate'`
	PluginCriticalCount string `json:"pluginCriticalCount"`
	PluginHighCount     string `json:"pluginHighCount"`
	PluginMediumCount   string `json:"pluginMediumCount"`
	PluginLowCount      string `json:"pluginLowCount"`
	PluginTotalCount    string `json:"pluginTotalCount"`

	ScanStart     string `json:"scanStart"`
	ScanStartUnix string `json:"scanStartUnix"`
	ScanEnd       string `json:"scanEnd"`
	ScanEndUnix   string `json:"scanEndUnix"`
	ScanDuration  string `json:"scanDuration"`

	Host       map[string]HostScanSummary `json:"hostMap"`
	HostPlugin map[string]PluginDetailSummary   `json:"hostPluginMap"`
	HostCount  string                           `json:"hostCount"`
}

type HostScanSummary struct {
	HostId              string `json:"hostId"`
	ScanDetail ScanHistoryDetail
  HostDetail HostScanDetail  
  PluginCriticalCount string `json:"pluginCriticalCount"`
  PluginHighCount     string `json:"pluginHighCount"`
  PluginMediumCount   string `json:"pluginMediumCount"`
  PluginLowCount      string `json:"pluginLowCount"`
  PluginTotalCount    string `json:"pluginTotalCount"`  
}

type HostScanDetail struct {
  FQDN             string                         `json:"hostFQDN"`
	IP               string                         `json:"hostIP"`
	NetBIOS          string                         `json:"hostNetBIOS"` //Windows only, but prevelant.
	MACAddresses     string                         `json:"hostMACAddresses"`
	OperatingSystems string                         `json:"hostOperatingSystems"`
	ScanStart        string                         `json:"hostScanStart"`
	ScanStartUnix    string                         `json:"hostScanStartUnix"`
	ScanEnd          string                         `json:"hostScanEnd"`
	ScanEndUnix      string                         `json:"hostScanEndUnix"`
	ScanDuration     string                         `json:"hostScanDuration"`
	Plugin           map[string]PluginDetailSummary `json:"hostPluginMap"`
}

type PluginDetailSummary struct {
	PluginId string `"json:pluginId"`
	Name     string `"json:pluginName"`
	Family   string `"json:pluginFamily"`
	Count    string `"json:pluginCount"`
	Severity string `"json:severityTypeId"`
	Detail   PluginDetail
}

type PluginDetail struct {
	RiskFactor            string `"json:riskFactor"`
	FunctionName          string `"json:functionName"`
	PluginPublicationDate string `"json:pluginPublicationDate"`
	PatchPublicationDate  string `"json:patchPublicationDate"`
	Attribute             map[string]PluginDetailAttribute
}
type PluginDetailAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
