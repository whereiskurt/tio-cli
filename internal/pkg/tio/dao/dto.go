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
	PolicyName       string `json:"policy_name"`
	Timestamp        string `json:"timestamp"`
}

type ScanDetailRecord struct {
	Scan              Scan
	TotalHistoryCount string `json:'totalHistoryCount'`
	HistoryRecords    []ScanDetailHistoryRecord
}

type ScanDetailHistoryRecord struct {
	Scan                Scan

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

	HostPlugins []SummaryPluginRecord `json:"plugins"`

	HostCount string                 `json:"hostCount"`
	Hosts     []HostScanPluginRecord `json:"hosts"`
}

type HostScanPluginRecord struct {
	ScanDetail ScanDetailHistoryRecord

	HostId               string `json:"hostId"`
	HostFQDN             string `json:"hostFQDN"`
	HostIP               string `json:"hostIP"`
	HostNetBIOS          string `json:"hostNetBIOS"` //Windows only, but prevelant.
	HostMACAddresses     string `json:"hostMACAddresses"`
	HostOperatingSystems string `json:"hostOperatingSystems"`

	HostScannerName   string `json:"hostScannerName"`
	HostScanStart     string `json:"hostScanStart"`
	HostScanStartUnix string `json:"hostScanStartUnix"`
	HostScanEnd       string `json:"hostScanEnd"`
	HostScanEndUnix   string `json:"hostScanEndUnix"`
	HostScanDuration  string `json:"hostScanDuration"`

	HostPlugins []HostPluginRecord `json:"hostPlugins"`
}

type SummaryPluginRecord struct {
	PluginId              string `"json:pluginId"`
	Name                  string `"json:pluginName"`
	Family                string `"json:pluginFamily"`
	Count                 string `"json:pluginCount"`
	Severity              string `"json:severityTypeId"`
}

type HostPluginRecord struct {
	PluginId              string `"json:pluginId"`
	Name                  string `"json:pluginName"`
	Family                string `"json:pluginFamily"`
	Count                 string `"json:pluginCount"`
	Severity              string `"json:severityTypeId"`
	RiskFactor            string `"json:riskFactor"`
	FunctionName          string `"json:functionName"`
	PluginPublicationDate string `"json:pluginPublicationDate"`
	PatchPublicationDate  string `"json:patchPublicationDate"`
	Attributes            []HostPluginRecordAttribute
}
type HostPluginRecordAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
