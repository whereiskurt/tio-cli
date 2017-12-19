package cmd

import (
  //"runtime/pprof"
  "strings"
  "bufio"
  "log"
  "fmt"
  "os"
  "time"
    
  homedir "github.com/mitchellh/go-homedir"
  
  "github.com/spf13/cobra"
  "github.com/spf13/viper"
  "tio-cli/cmd/vulnerability"
  "tio-cli/cmd/colour"
)
 
var CliAppVersion = "20171218"

//TODO: Use util.go!
var BOLD = colour.BOLD
var RESET = colour.RESET
var GREEN = colour.GREEN
var RED = colour.RED
var GREY = colour.GREY


// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
  SilenceUsage: true,
  DisableSuggestions: true,
	Use:   "tio-cli [scans|hosts|history]",
	Short: "Interact with Tenable.IO cloud",
	Long: `
_|_ o  _ --- _  |  o 
 |_ | (_)   (_  |  |  [Release 0.1 Version `+GREEN+CliAppVersion+RESET+`]
------------------------------------------------------------------------>
A command line tool for accessing Tenable.IO
                                              `+GREY+`(written in Golang!)`+RESET+`
`+BOLD+`OVERVIEW`+RESET+`
tio-cli is a command line tool for accesses the Tenable.IO vulnerability portal. This is 
convenient for reviewing scans, hosts, and vulnerabilities with-out using a web-browser.

tio-cli produces CSV output that can aid in analysis and report writing. To run, 
only access and secret keys are required.  On first run, a default configuration 
file will be created after prompting for the accessKey and secretKey.

`+BOLD+`Access and Secret Keys:`+RESET+`
In the $HOMEDIR tio-cli will create a '.tio-cli.yaml' with these two lines:

  accessKey: `+RED+`0123456789ABCDEF0123...`+RESET+`(64chars)
  secretKey: `+RED+`0123456789ABCDEF0123...`+RESET+`(64chars)

`+BOLD+`USAGE`+RESET+`
There are three major areas to tio-cli: scans, hosts and history

  `+BOLD+`SCANS`+RESET+` - Output details of scans that have happened:
  `+GREY+`##Output all the scans`+RESET+`
  $ ./tio `+GREEN+`scans`+RESET+`
  `+GREY+`##Output scans details for scan's 1 and 2`+RESET+`
  $ ./tio `+GREEN+`scans`+RESET+` --scanid 1,2

  `+BOLD+`HOSTS`+RESET+` - Output host details from a scan:
  `+GREY+`##Output all hosts from all scans`+RESET+`
  $ ./tio `+GREEN+`hosts`+RESET+`
  `+GREY+`##Output all hosts from scan 1 and 2`+RESET+`
  $ ./tio `+GREEN+`hosts`+RESET+` --scanid 1,2
  `+GREY+`##Output all hosts from the previous scan 1 and 2 (historical)`+RESET+`
  $ ./tio `+GREEN+`hosts`+RESET+` --scanid 1,2 --previous 1  
  `+GREY+`##Output any host that matches plugin 10042, 97833 or 88906`+RESET+`
  $ ./tio `+GREEN+`hosts`+RESET+` --plugins 10042,97833,88906
  `+GREY+`##Output any host that matched plugin 10042, 97833 or 88906 on previous scan`+RESET+`
  $ ./tio `+GREEN+`hosts`+RESET+` --plugins 10042,97833,88906 --previous 1
  `+GREY+`##Output any host that matches plugin 10042, 97833 or 88906 from scan's 1 and 2`+RESET+`
  $ ./tio `+GREEN+`hosts`+RESET+`  --scanid 1,2 --plugins 10042,97833,88906

  `+BOLD+`HISTORY`+RESET+` - Output when a host matched a plugin (ie. first match, last match, etc)
  `+GREY+`##Output any host from scans 1 and 2 that matched plugin 10042 in the last 12 scans`+RESET+`
  $ ./tio `+GREEN+`history`+RESET+` --scanid 1,2 --plugins 100424 --depth 12
`,
}
//http://patorjk.com/software/taag/#p=display&f=Bigfig&t=tio-cli

type Params struct {
  ConfigFile string
  AccessKey string
  SecretKey string
  CacheKey string
  BaseUrl string
  Version bool

  UseAllHosts bool
  Scans string
  Historical string
  
  Previous string
  Depth string

  IncludePlugins string

  ByHostIP bool
  ByHostFQDN bool

  CacheFolder string
  UseCryptoCache bool


  IgnoreScan string
  IgnoreHistory string
  Verbosity string
  Quiet bool
  NoColour bool

  TZDefault string

}
var p Params

func Execute() {
  ///////////////////////////////////////
  //PROFILING BLOCK:
  //import (
  // "runtime/pprof"
  // )
  //////
  //Uncomment to create detailed call stats etc.
  // f, err := os.Create("tio.prof")
  // if err != nil {
  //     log.Fatal(err)
  // }
  // pprof.StartCPUProfile(f)
  // defer pprof.StopCPUProfile()

  RootCmd.SetUsageTemplate(" ")

  if err := RootCmd.Execute(); err != nil {
    log.Fatal(err)
  }

}

func init() { 
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&p.ConfigFile, "config", "", "config file (default is $HOME/.tio-cli.yaml) must end '.yaml'")
  
	RootCmd.PersistentFlags().StringVar(&p.BaseUrl, "baseUrl", "https://cloud.tenable.com", "Base url.")
  RootCmd.PersistentFlags().StringVar(&p.AccessKey, "accessKey", "", "Tenable.IO accessKey token.")
  RootCmd.PersistentFlags().StringVar(&p.SecretKey, "secretKey", "", "Tenable.IO secretKey token.")
  RootCmd.PersistentFlags().StringVar(&p.CacheKey, "cacheKey", "", "A secret key for local cache.")
  
  RootCmd.PersistentFlags().StringVar(&p.CacheFolder, "cacheFolder", "./cache/", "Where to find the default cache folder.")
  RootCmd.PersistentFlags().BoolVar(&p.UseCryptoCache, "useCryptoCache", true, "Use the cache key and encrypt local cache (default:true).")
  
  RootCmd.PersistentFlags().StringVar(&p.Scans, "scan", "", "Comma separate list of plugins to include.")
  RootCmd.PersistentFlags().StringVar(&p.Scans, "scans", "", "Comma separate list of plugins to include.")
  RootCmd.PersistentFlags().StringVar(&p.Scans, "scanid", "", "Comma separate list of plugins to include.")
  RootCmd.PersistentFlags().StringVar(&p.Scans, "scanids", "", "Comma separate list of plugins to include.")

  RootCmd.PersistentFlags().StringVar(&p.IncludePlugins, "plugin", "", "List of Tenable.IO plugins to include.")
  RootCmd.PersistentFlags().StringVar(&p.IncludePlugins, "plugins", "", "List of Tenable.IO plugins to include.")

  RootCmd.PersistentFlags().StringVar(&p.Previous, "previous", "0", "Set to 1 to use previous scan results.")
  RootCmd.PersistentFlags().StringVar(&p.Previous, "prev", "0", "Set to 1 to use previous scan results.")
  
  RootCmd.PersistentFlags().StringVar(&p.Depth, "depth", "2", "Defines how many past scans to include.")

  RootCmd.PersistentFlags().StringVar(&p.IgnoreScan, "ignoreScan", "", "Comma list of scanids to ignore..")
  RootCmd.PersistentFlags().StringVar(&p.IgnoreScan, "ignoreScans", "", "Comma list of scanids to ignore..")

  RootCmd.PersistentFlags().StringVar(&p.IgnoreHistory, "ignoreHistory", "", "Comma list of histories to ignore..")
  RootCmd.PersistentFlags().StringVar(&p.Verbosity, "verbosity", "1", "Level 1-5 for amount of output details.")
  RootCmd.PersistentFlags().BoolVar(&p.Quiet, "quiet", false, "Disable all output, except for errors (--verbosity == 0)")

  RootCmd.PersistentFlags().StringVar(&p.TZDefault, "tzDefault", "-0600 CST", "Default TZ for scan results to be presented.")
  RootCmd.PersistentFlags().StringVar(&p.TZDefault, "tz", "-0600 CST", "Default TZ for scan results to be presented.")
  
  RootCmd.PersistentFlags().BoolVar(&p.ByHostIP, "byHostIP", true, "Use IP address of host for tracking uniqueness.")
  RootCmd.PersistentFlags().BoolVar(&p.ByHostFQDN, "byHostFQDN", false, "Use FQDN for reducing hosts (is false, uses HostIP by default.)")

  RootCmd.PersistentFlags().BoolVar(&p.NoColour, "nocolour", false, "Disable all colour output. (false))")

  viper.BindPFlag("accessKey", RootCmd.PersistentFlags().Lookup("accessKey"))
  viper.BindPFlag("secretKey", RootCmd.PersistentFlags().Lookup("secretKey"))
  viper.BindPFlag("cacheKey", RootCmd.PersistentFlags().Lookup("cacheKey"))
  viper.BindPFlag("cacheFolder", RootCmd.PersistentFlags().Lookup("cacheFolder"))
  viper.BindPFlag("useCryptoCache", RootCmd.PersistentFlags().Lookup("useCryptoCache"))

  viper.BindPFlag("baseUrl", RootCmd.PersistentFlags().Lookup("baseUrl"))

  viper.BindPFlag("scanid", RootCmd.PersistentFlags().Lookup("scanid"))
  viper.BindPFlag("plugins", RootCmd.PersistentFlags().Lookup("plugins"))

  viper.BindPFlag("depth", RootCmd.PersistentFlags().Lookup("depth"))
  
  viper.BindPFlag("previous", RootCmd.PersistentFlags().Lookup("previous"))
  
  viper.BindPFlag("ignoreScans", RootCmd.PersistentFlags().Lookup("ignoreScans"))
  viper.BindPFlag("ignoreHistory", RootCmd.PersistentFlags().Lookup("ignoreHistory"))
  viper.BindPFlag("verbosity", RootCmd.PersistentFlags().Lookup("verbosity"))
  viper.BindPFlag("quiet", RootCmd.PersistentFlags().Lookup("quiet"))

  viper.BindPFlag("byHostIP", RootCmd.PersistentFlags().Lookup("byHostIP"))
  viper.BindPFlag("byHostFQDN", RootCmd.PersistentFlags().Lookup("byHostFQDN"))
  
  viper.BindPFlag("nocolour", RootCmd.PersistentFlags().Lookup("nocolour"))

  RootCmd.AddCommand(vulnerability.ScanCmd)
  RootCmd.AddCommand(vulnerability.HistoryCmd)
  RootCmd.AddCommand(vulnerability.HostsCmd)
  RootCmd.AddCommand(vulnerability.CacheCmd)
}

func initConfig() {
  // Find home directory.
  home, err := homedir.Dir()
  if err != nil {
    log.Fatal(err)
  }

	if p.ConfigFile != "" {
		viper.SetConfigFile(p.ConfigFile)
	} else {
		// Search config in home directory with name ".tio-cli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".tio-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

  err = viper.ReadInConfig()
	if err != nil {
    uiGenerateConfigKeys(home)
	}

  if viper.GetBool("nocolour") {
    colour.DisableColour()
  }

}

func uiGenerateConfigKeys( home string ) {
  fmt.Println( fmt.Sprintf(BOLD + "WARN: " + RESET + "No configuration file '.tio-cli.yaml' found in '%s' .", home)) 
  fmt.Println() 
  fmt.Print(BOLD, "Is this your first execution? Need access keys for API usage.", RESET)
  fmt.Println() 

  fmt.Println( fmt.Sprintf("You must provide the X-ApiKeys 'accessKey' and 'secretKey' to access the API.")) 
  fmt.Println( fmt.Sprintf("For complete details see: https://cloud.tenable.com/api#/authorization")) 
  fmt.Println() 
  
  reader := bufio.NewReader(os.Stdin)
  fmt.Print("Enter required ", BOLD, "'accessKey'", RESET, ": ")
  p.AccessKey, _ = reader.ReadString('\n')
  p.AccessKey = strings.TrimSpace(p.AccessKey)
  if len(p.AccessKey) != 64 {
    log.Fatal( fmt.Sprintf("Invalid accessKey '%s' length %d not 64.\n\n", p.AccessKey, len(p.AccessKey))) 
  }

  fmt.Print("Enter required ", BOLD, "'secretKey'", RESET, ": ")
  p.SecretKey, _ = reader.ReadString('\n')
  p.SecretKey = strings.TrimSpace(p.SecretKey)
  if len(p.SecretKey) != 64 {
    log.Fatal( fmt.Sprintf("Invalid secretKey '%s' length %d not 64.\n\n", p.SecretKey, len(p.SecretKey))) 
  }

  fmt.Println()
  fmt.Print("Save configuration file? [yes or ", BOLD, "no (default is 'no')", RESET, "): ")
  shouldSave, _ := reader.ReadString('\n')
  fmt.Println()

  if len(shouldSave) > 0 && strings.ToUpper(shouldSave)[0] == 'Y' {
    log.Println( fmt.Sprintf("Creating default '.tio-cli.yaml' in '%s' .", home)) 
    
    file, err := os.Create(home + "/.tio-cli.yaml")
    if err != nil {
        log.Fatal("Cannot create file:", BOLD, err, RESET, "\n\n")
    }
    defer file.Close()
    log.Println( fmt.Sprintf("Writing 'accessKey' and 'seretKey'...")) 
    fmt.Fprintf(file, "accessKey: %s\n", p.AccessKey)
    fmt.Fprintf(file, "secretKey: %s\n", p.SecretKey)

    fmt.Fprintf(file, "cacheKey: %s%s\n", p.AccessKey[:16], p.SecretKey[:16])
    fmt.Fprintf(file, "cacheFolder: %s\n", "./cache/")

    log.Println( fmt.Sprintf("Done! \nWriting default timezone ...")) 
    t := time.Now()
    ts := fmt.Sprintf("%v", t)
    tzDefault := ts[len(ts)-10:]
    fmt.Fprintf(file, "tzDefault: %s", tzDefault)

    
    log.Println( fmt.Sprintf("Done! \nSuccessfully created '%v/.tio-cli.yaml'", home)) 
  }

  return
}
