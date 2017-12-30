package dao

type Scan struct {
	ScanId           string `json:"id"`
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	Status           string `json:"status"`
	Owner            string `json:"owner"`
	UserPermissions  string `json:"user_permissions"`
	Enabled          string `json:"enabled"`
	RRules           string `json:"rrules"`
	Timezone         string `json:"timezone"`
	StartTime        string `json:"startTime"`
	CreationDate     string `json:"creation_date"`
	LastModifiedDate string `json:"last_modification_date"`
	Timestamp        string `json:"timestamp"`
}

type ScanDetailRecord struct {
	Scan
	PolicyName        string `json:"policy_name"`
	TotalHistoryCount string `json:'totalHistoryCount'`
	HistoryRecords    []ScanDetailHistoryRecord
}

type ScanDetailHistoryRecord struct {
	HistoryId           string                 `json:"historyId"`
	Status              string                 `json:"status"`
	CreationDate        string                 `json:'createDate'`
	LastModifiedDate    string                 `json:'lastModifiedDate'`
	PluginCriticalCount string                 `json:"pluginCriticalCount"`
	PluginHighCount     string                 `json:"pluginHighCount"`
	PluginMediumCount   string                 `json:"pluginMediumCount"`
	PluginLowCount      string                 `json:"pluginLowCount"`
	PluginTotalCount    string                 `json:"pluginTotalCount"`
	HostCount           string                 `json:"hostCount"`
	Plugins             []PluginRecord         `json:"plugins"`
	Hosts               []HostScanPluginRecord `json:"hosts"`
}

type PluginRecord struct {
	PluginId              string `"json:pluginId"`
	Name                  string `"json:pluginName"`
	Family                string `"json:pluginFamily"`
	Count                 string `"json:pluginCount"`
	Severity              string `"json:severityTypeId"`
	RiskFactor            string `"json:riskFactor"`
	FunctionName          string `"json:functionName"`
	PluginPublicationDate string `"json:pluginPublicationDate"`
	PatchPublicationDate  string `"json:patchPublicationDate"`
	Attributes            []PluginRecordAttribute
}
type PluginRecordAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HostScanPluginRecord struct {
	ScanId       string `json:"scanId"`
	HostId       string `json:"hostId"`
	HistoryId    string `json:"historyId"`
	HistoryIndex string `json:"historyIndex"`

	ScanName       string `json:"scanName"`
	ScanPolicyName string `json:"scanPolicyName"`

	ScanStart     string `json:"scanStart"`
	ScanStartUnix string `json:"scanStartUnix"`
	ScanEnd       string `json:"scanEnd"`
	ScanEndUnix   string `json:"scanEndUnix"`
	ScanDuration  string `json:"scanDuration"`

	HostFQDN        string `json:"hostFQDN"`
	HostIP          string `json:"hostIP"`
	HostScannerName string `json:"hostScannerName"`

	HostScanStart     string `json:"hostScanStart"`
	HostScanStartUnix string `json:"hostScanStartUnix"`
	HostScanEnd       string `json:"hostScanEnd"`
	HostScanEndUnix   string `json:"hostScanEndUnix"`
	HostScanDuration  string `json:"hostScanDuration"`

	HostNetBIOS string `json:"hostNetBIOS"` //Windows only, but prevelant.

	HostMACAddresses     string `json:"hostMACAddresses"`
	HostOperatingSystems string `json:"hostOperatingSystems"`

	HostPlugins []PluginRecord `json:"hostPlugins"`

	PluginCriticalCount string `json:"pluginCriticalCount"`
	PluginHighCount     string `json:"pluginHighCount"`
	PluginMediumCount   string `json:"pluginMediumCount"`
	PluginLowCount      string `json:"pluginLowCount"`
	PluginTotalCount    string `json:"pluginTotalCount"`
}
