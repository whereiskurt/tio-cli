package ui

import (
  "bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/dao"
)

type CommandLineInterface struct {
	Config            *tio.BaseConfig
	Workers           *sync.WaitGroup
	ConcurrentWorkers int
	Output *os.File
}

func NewCommandLineInterface(config *tio.BaseConfig) *CommandLineInterface {
	c := new(CommandLineInterface)
	
	c.Config = config
	c.Workers = new(sync.WaitGroup)
	c.ConcurrentWorkers, _ = strconv.Atoi(config.ConcurrentWorkers)
	c.Output = config.Output

	if c.Config.NoColourMode {
		DisableColour()
	}

	return c
}

func (cli *CommandLineInterface) DrawGopher() {
  
  cli.Println("         ,_---~~~~~----._         ")
  cli.Println("  _,,_,*^____      _____``*g*\"*,")
  cli.Println(" / __/ /'     ^.  /      \\ ^@q   ")
  cli.Println("[  @f | @))    |  | @))   l  0 _/")
  cli.Println(" \\`/   \\~____ / __ \\_____/    \\")
  cli.Println("  |           _l__l_           I")
  cli.Println("  }          [______]           I")
  cli.Println("  ]            | | |            |")
  cli.Println("  ]             ~ ~             |") 
  cli.Println("  |                            |") 
  cli.Println("   |                           |")  
  //Sourced!:https://gist.github.com/belbomemo/b5e7dad10fa567a5fe8a

}
func (cli *CommandLineInterface) Println(line ... interface{}) {
	fmt.Fprintln(cli.Output, fmt.Sprintf("%v", line ...))
  return
}
func (cli *CommandLineInterface) Print(line ... interface{}) {
  fmt.Fprintf(cli.Output, fmt.Sprintf("%v", line ... ))
	return
}

func UnixTimePretty(unix string) string {
	var rawUnixInt, err = strconv.ParseInt(string(unix), 10, 64)
	if err != nil {
		rawUnixInt = int64(0)
	}
	var unixFirstStart = time.Unix(rawUnixInt, 0)

	var prettyDate = fmt.Sprintf("%v", unixFirstStart)

	return prettyDate
}

func (cli *CommandLineInterface) DrawShortTable(recs []dao.ScanHistory) {

	table := tablewriter.NewWriter(cli.Output)

	table.SetHeader([]string{"ID", "Name", "Status", "#Hosts", "#CRIT/H/M/L", "LastRun", "#Hists."})
	table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})
	table.SetBorder(true)
	table.SetAutoWrapText(false)

	data := [][]string{}
	for _, record := range recs {
		outRec := []string{record.Scan.ScanId}

		//fmt.Printf(fmt.Sprintf("Record: %+v\n\n", record))
		status := strings.TrimSpace(record.Scan.Status)
		if status == "empty" {
			status = CNEVER + "never" + RESET
		} else if status == "running" {
			status = CRUNNING + "running" + RESET
		}

		if len(record.Scan.Name) > 40 {
			record.Scan.Name = record.Scan.Name[:40] + "..."
		}

		outRec = append(outRec, record.Scan.Name, status)

		if len(record.ScanHistoryDetails) > 0 {
			lastRun := record.ScanHistoryDetails[0]

			if lastRun.PluginCriticalCount != "" && lastRun.PluginCriticalCount != "0" {
				lastRun.PluginCriticalCount = CCRIT + lastRun.PluginCriticalCount + RESET
			}
			if lastRun.PluginHighCount != "" && lastRun.PluginHighCount != "0" {
				lastRun.PluginHighCount = CHIGH + lastRun.PluginHighCount + RESET
			}
			if lastRun.PluginMediumCount != "" && lastRun.PluginMediumCount != "0" {
				lastRun.PluginMediumCount = CMED + lastRun.PluginMediumCount + RESET
			}
			if lastRun.PluginLowCount != "" && lastRun.PluginLowCount != "0" {
				lastRun.PluginLowCount = CLOW + lastRun.PluginLowCount + RESET
			}

			vulnStr := fmt.Sprintf("%s,%s,%s,%s", lastRun.PluginCriticalCount, lastRun.PluginHighCount, lastRun.PluginMediumCount, lastRun.PluginLowCount)
			if vulnStr == ",,," {
				vulnStr = "-"
			}
			outRec = append(outRec, lastRun.HostCount, vulnStr, UnixTimePretty(lastRun.LastModifiedDate)[:10])
		} else {
			outRec = append(outRec, "-", "-", "0")
		}
		outRec = append(outRec, record.ScanHistoryCount)

		data = append(data, outRec)
	}

	table.AppendBulk(data)

	table.Render()
	return
}

func (cli *CommandLineInterface) DrawDashboard(recs []dao.ScanHistory) {
	table := tablewriter.NewWriter(cli.Output)
	table.SetHeader([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "#HOSTS"})
	table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})

	data := [][]string{{}}
	val := []int64{0, 0, 0, 0, 0}
	for _, r := range recs {
		if len(r.ScanHistoryDetails) > 0 {
			crit, _ := strconv.ParseInt(string(r.ScanHistoryDetails[0].PluginCriticalCount), 10, 64)
			high, _ := strconv.ParseInt(string(r.ScanHistoryDetails[0].PluginHighCount), 10, 64)
			medium, _ := strconv.ParseInt(string(r.ScanHistoryDetails[0].PluginMediumCount), 10, 64)
			low, _ := strconv.ParseInt(string(r.ScanHistoryDetails[0].PluginLowCount), 10, 64)
			hostcount, _ := strconv.ParseInt(string(r.ScanHistoryDetails[0].HostCount), 10, 64)

			val[0] = val[0] + crit
			val[1] = val[1] + high
			val[2] = val[2] + medium
			val[3] = val[3] + low
			val[4] = val[4] + hostcount
		}
	}
	data = append(data, []string{CCRIT + fmt.Sprintf("%v", val[0]) + RESET, CHIGH + fmt.Sprintf("%v", val[1]) + RESET, CMED + fmt.Sprintf("%v", val[2]) + RESET, fmt.Sprintf("%v", val[3]), CCNT + fmt.Sprintf("%v", val[4]) + RESET})

	table.AppendBulk(data)
	table.Render()

	fmt.Printf(BOLD + "Total Scans Counted: " + RESET)
	fmt.Println(CCNT + fmt.Sprintf("%v", len(recs)) + RESET)
	fmt.Println()
	return
}

func (cli *CommandLineInterface) DrawRunSchedule(r dao.ScanHistory) {

	table := tablewriter.NewWriter(cli.Output)
	table.SetHeader([]string{"Enabled", "RunRule", "StartTime"})
	table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})

	data := [][]string{{r.Scan.Enabled, r.Scan.RRules, r.Scan.StartTime}}
	table.AppendBulk(data)
	table.Render()
}

func (cli *CommandLineInterface) DrawRunHistory(r dao.ScanHistory) {

	if len(r.ScanHistoryDetails) == 0 {
		return
	}

	table := tablewriter.NewWriter(cli.Output)
	table.SetHeader([]string{"HistoryID", "Status", "#Hosts", "#CRIT/H/M/L", "LastRun"})
	table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})

	data := [][]string{}
	for _, h := range r.ScanHistoryDetails {
		outRec := []string{h.HistoryId, h.Status}

		if h.PluginCriticalCount != "0" {
			h.PluginCriticalCount = CCRIT + h.PluginCriticalCount + RESET
		}
		if h.PluginHighCount != "0" {
			h.PluginHighCount = CHIGH + h.PluginHighCount + RESET
		}
		if h.PluginMediumCount != "0" {
			h.PluginMediumCount = CMED + h.PluginMediumCount + RESET
		}
		if h.PluginLowCount != "0" {
			h.PluginLowCount = CLOW + h.PluginLowCount + RESET
		}
		vulnStr := fmt.Sprintf("%v,%v,%v,%v", h.PluginCriticalCount, h.PluginHighCount, h.PluginMediumCount, h.PluginLowCount)
		if vulnStr == ",,," {
			vulnStr = "0,0,0,0"
		}
		outRec = append(outRec, h.HostCount, vulnStr, UnixTimePretty(h.LastModifiedDate)[:10])

		data = append(data, outRec)
	}
	table.AppendBulk(data)
	table.Render()
}

func (cli *CommandLineInterface) DrawHosts(r dao.ScanHistoryDetail, hostKeys []string) {
	if len(r.Host) == 0 {
		return
	}

	table := tablewriter.NewWriter(cli.Output)
	table.SetHeader([]string{"ID", "IP", "Names", "#CRIT/H/M/L", "OS"})
	table.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})

	data := [][]string{}

	for _, key := range hostKeys {
		h := r.Host[key]

		name := h.HostDetail.FQDN
		if name != h.HostDetail.NetBIOS {
			name = strings.Join([]string{h.HostDetail.FQDN, h.HostDetail.NetBIOS}, " ")
		}
		if name == " " {
			name = "[UNKNOWN]"
		}

		if len(h.HostDetail.OperatingSystems) > 30 {
			h.HostDetail.OperatingSystems = h.HostDetail.OperatingSystems[:30]
		}
		os := h.HostDetail.OperatingSystems

		if h.PluginCriticalCount != "0" {
			h.PluginCriticalCount = CCRIT + h.PluginCriticalCount + RESET
		}
		if h.PluginHighCount != "0" {
			h.PluginHighCount = CHIGH + h.PluginHighCount + RESET
		}
		if h.PluginMediumCount != "0" {
			h.PluginMediumCount = CMED + h.PluginMediumCount + RESET
		}
		if h.PluginLowCount != "0" {
			h.PluginLowCount = CLOW + h.PluginLowCount + RESET
		}

		vulnStr := fmt.Sprintf("%v,%v,%v,%v", h.PluginCriticalCount, h.PluginHighCount, h.PluginMediumCount, h.PluginLowCount)
		if vulnStr == ",,," {
			vulnStr = "-"
		}
		data = append(data, []string{h.HostId, h.HostDetail.IP, name, vulnStr, os})
	}

	if len(data) > 0 {
		table.AppendBulk(data)
		table.Render()
	} else {
		fmt.Println(BOLD + "---> NONE!" + RESET)
	}
}

func (cli *CommandLineInterface) DrawScanVulnTable(rec dao.ScanHistoryDetail, vulnKeys []string) {
	table := tablewriter.NewWriter(cli.Output)
	table.SetHeader([]string{"ID", "Name", "Family,", "SEV", "#"})
	table.SetColumnAlignment([]int{tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER})
	table.SetAutoWrapText(false)

	data := [][]string{}

	for _, key := range vulnKeys {
		p := rec.HostPlugin[key]
		//  }
		// for _, p := range rec.HostPlugin {
		sev, _ := strconv.ParseInt(p.Severity, 10, 64)
		var sevWord []string = []string{CINFO + "INFO" + RESET, CLOW + "LOW" + RESET, CMED + "MED" + RESET, CHIGH + "HIGH" + RESET, CCRIT + "CRIT" + RESET}
		if len(p.Name) > 45 {
			p.Name = p.Name[:45]
		}
		outRec := []string{p.PluginId, p.Name, p.Family, sevWord[sev], p.Count}
		data = append(data, outRec)
	}

	if len(data) > 0 {
		table.AppendBulk(data)
		table.Render()
	} else {
		fmt.Println(BOLD + "---> NONE!" + RESET)
	}
}

func (cli *CommandLineInterface) PromptForConfigKeys() {
  home := cli.Config.HomeDir

  cli.Println( fmt.Sprintf(BOLD + "WARN: " + RESET + "No configuration file '.tio-cli.yaml' found in '%s' .", home)) 
  cli.Println("") 
  cli.Print(fmt.Sprintf(BOLD + "Is this your first execution? Need access keys for API usage." + RESET))
  cli.Println("") 

  cli.Println( fmt.Sprintf("You must provide the X-ApiKeys 'accessKey' and 'secretKey' to access the API.")) 
  cli.Println( fmt.Sprintf("For complete details see: https://cloud.tenable.com/api#/authorization")) 
  cli.Println("") 
  
  reader := bufio.NewReader(os.Stdin)
  cli.Print(fmt.Sprintf("Enter required "+BOLD+"'accessKey'"+RESET+": "))
  cli.Config.AccessKey, _ = reader.ReadString('\n')
  cli.Config.AccessKey = strings.TrimSpace(cli.Config.AccessKey)
  if len(cli.Config.AccessKey) != 64 {
    panic( fmt.Sprintf("Invalid accessKey '%s' length %d not 64.\n\n", cli.Config.AccessKey, len(cli.Config.AccessKey))) 
  }

  cli.Print("Enter required ", BOLD, "'secretKey'", RESET, ": ")
  cli.Config.SecretKey, _ = reader.ReadString('\n')
  cli.Config.SecretKey = strings.TrimSpace(cli.Config.SecretKey)
  if len(cli.Config.SecretKey) != 64 {
    panic( fmt.Sprintf("Invalid secretKey '%s' length %d not 64.\n\n", cli.Config.SecretKey, len(cli.Config.SecretKey))) 
  }

  cli.Println()
  cli.Print("Save configuration file? [yes or ", BOLD, "no (default is 'no')", RESET, "): ")
  shouldSave, _ := reader.ReadString('\n')
  cli.Println()

  if len(shouldSave) > 0 && strings.ToUpper(shouldSave)[0] == 'Y' {
    cli.Println( fmt.Sprintf("Creating default '.tio-cli.yaml' in '%s' .", home)) 
    
    file, err := os.Create(home + "/.tio-cli.yaml")
    if err != nil {
      panic(fmt.Sprintf("Cannot create file:", BOLD, err, RESET, "\n\n"))
    }
    defer file.Close()
    cli.Println( fmt.Sprintf("Writing 'accessKey' and 'seretKey'...")) 

    fmt.Fprintf(file, "accessKey: %s\n", cli.Config.AccessKey)
    fmt.Fprintf(file, "secretKey: %s\n", cli.Config.SecretKey)
    fmt.Fprintf(file, "cacheKey: %s%s\n", cli.Config.AccessKey[:16], cli.Config.SecretKey[:16])
    fmt.Fprintf(file, "cacheFolder: %s\n", "./cache/")

    cli.Println( fmt.Sprintf("Done! \nWriting default timezone ...")) 
    t := time.Now()
    ts := fmt.Sprintf("%v", t)
    tzDefault := ts[len(ts)-10:]
    fmt.Fprintf(file, "tzDefault: %s", tzDefault)

    cli.Println( fmt.Sprintf("Done! \nSuccessfully created '%v/.tio-cli.yaml'", home)) 
  }

  return
}
