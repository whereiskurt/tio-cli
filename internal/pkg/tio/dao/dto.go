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

	HostPlugins []PluginDetailSummary `json:"plugins"`

	HostCount string                  `json:"hostCount"`
	Hosts     []HostScanDetailSummary `json:"hosts"`
}

type HostScanDetailSummary struct {
	HostId     string `json:"hostId"`
	ScanDetail ScanHistoryDetail
}

type HostScanDetail struct {
	HostScanDetailSummary

	HostFQDN             string `json:"hostFQDN"`
	HostIP               string `json:"hostIP"`
	HostNetBIOS          string `json:"hostNetBIOS"` //Windows only, but prevelant.
	HostMACAddresses     string `json:"hostMACAddresses"`
	HostOperatingSystems string `json:"hostOperatingSystems"`

	HostScanStart     string `json:"hostScanStart"`
	HostScanStartUnix string `json:"hostScanStartUnix"`
	HostScanEnd       string `json:"hostScanEnd"`
	HostScanEndUnix   string `json:"hostScanEndUnix"`
	HostScanDuration  string `json:"hostScanDuration"`

	HostPlugins []PluginDetail `json:"hostPlugins"`
}

type PluginDetailSummary struct {
	PluginId string `"json:pluginId"`
	Name     string `"json:pluginName"`
	Family   string `"json:pluginFamily"`
	Count    string `"json:pluginCount"`
	Severity string `"json:severityTypeId"`
}

type PluginDetail struct {
	PluginDetailSummary
	RiskFactor            string `"json:riskFactor"`
	FunctionName          string `"json:functionName"`
	PluginPublicationDate string `"json:pluginPublicationDate"`
	PatchPublicationDate  string `"json:patchPublicationDate"`
	Attributes            []PluginDetailAttribute
}
type PluginDetailAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
