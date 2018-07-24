package tio

import (
	"os"
	"reflect"
)

type ReflectIntoConfig interface {
	SetString(field string, value string)
	SetBool(field string, value bool)
}

type BaseConfig struct {
	IsSuccessState     bool
	HomeDir            string
	ExecutionDTS       string
	ConfigFile         string
	Verbose            string
	BaseUrl            string
	AccessKey          string
	SecretKey          string
	CacheKey           string
	CacheFolder        string
	CacheDisabled      bool
	UseCryptoCache     bool
	QuietMode          bool
	OfflineMode        bool
	NoColourMode       bool
	DisplayVersionMode bool
	LogFilename        string
	LogFolder          string
	LogFileAppend      bool

	DefaultTimezone string

	OutputFilename   string
	OutputFolder     string
	OutputFileAppend bool
	OutputCSVMode    bool
	OutputJSONMode   bool

	ConcurrentWorkers string
	DisplayGUIMode    bool

	LogFileHandle *os.File
	Logger        *Logger

	Output *os.File
}

// func (config *BaseConfig) String() string {
//  //Use this to mask the Access/Secret/CacheKeys from outputs
// 	return fmt.Sprintf("BaseConfig: BLAHBLAHLBAH")
// }

// func (config *VulnerabilityConfig) String() string {
// 	return fmt.Sprintf("VulnConfig: BLAHBLAHLBAH")
// }

type VulnerabilityConfig struct {
	Base            *BaseConfig
	Previous        string
	Depth           string
	DetailView      bool
	ListView        bool
	ScanId          string
	IgnoreScanId    string
	HistoryId       string
	IgnoreHistoryId string
	AssetId         string
	IgnoreAssetId   string
	PluginId        string
	IgnorePluginId  string

	ShouldAnon bool
	SyncMode   bool
	PurgeMode  bool

	CacheFolderWrite string
}

func NewBaseConfig() *BaseConfig {
	c := new(BaseConfig)

	return c
}
func NewVulnerabilityConfig() *VulnerabilityConfig {
	c := new(VulnerabilityConfig)
	c.Base = NewBaseConfig()
	return c
}

func (config *BaseConfig) SetString(field string, value string) {
	v := reflect.ValueOf(config).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetString(value)
	}
	return
}
func (vulnConfig *VulnerabilityConfig) SetString(field string, value string) {
	v := reflect.ValueOf(vulnConfig).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetString(value)
	}
	return
}
func (config *BaseConfig) SetBool(field string, value bool) {
	v := reflect.ValueOf(config).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetBool(value)
	}
	return
}
func (vulnConfig *VulnerabilityConfig) SetBool(field string, value bool) {
	v := reflect.ValueOf(vulnConfig).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetBool(value)
	}
	return
}
