![porject logo topher](https://github.com/whereiskurt/tio-cli/blob/master/docs/topher.tiny.png)

# A Tool for the Tenable.IO API - v0.1 [20171218] :rocket:
`tio-cli` is a command line tool for interacting with the Tenable.IO API, written in golang. It only supports a very small set of the [Tenable.IO API](https://cloud.tenable.com/api) around scans, plugins, and hosts but has been a useful **proof of concept project**.  

`tio-cli` was written by KPH (@whereiskurt) and **is not supported or endorsed by Tenable in anyway.**

# tl;dr
  `tio-cli` was initially created to:
- [X] Gain deeper insight into my Tenable.IO data in a CLI way.
- [x] Learn golang (and the Tenable.IO APIs)
- [x] Have fun with an unconstrained **proof-of-concept project**!

# Overview
[Tenable.IO](https://cloud.tenable.com) is a modern webapp rendered in web browser - a **G**raphical **U**ser **I**nterfaces (**GUI**). `tio-cli` is a **C**ommand **L**ine **I**nterface (**CLI**) tool that can query scans, plugins, hosts and historical details from the Tenable.IO using typed commands and [Tenable.IO's published API](https://cloud.tenable.com/api). The commands results are generally comma separated values (CSV) or textual/byte summaries, which are ideal for importing into a spreadsheets or databases (unlike webpages, images and PDFs.)

To try `tio-cli` without setting up a golang development environment the [`"bin/"`](https://github.com/whereiskurt/tio-cli/tree/master/bin) folder has precompiled binaries available for a few platforms.  For Windows:
```
   1) Make directory like "`c:\tio`"
   2) Download the "`tio64.exe`"
   3) Open a 'cmd.exe' or 'powershell.exe' shell
   4) cd c:\tio 
  5a) tio64.exe scans
      or
  5b) tio64.exe scans --nocolour
```
**NOTE:** You may need to add "`--nocolour`" to Windows outputs if garbled.

Otherwise, if you do have a golang environment setup follow these faily common steps to get golang running the code:
```
   $ cd $GOPATH/src
   $ git clone https://github.com/whereiskurt/tio-cli.git
   $ cd tio-cli
   $ go get
   $ go run tio.go scans
```
![tio-cli scans output](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/scanlist.png)

# First Run - You'll need keys please!
If you don't have a golang development environment setup consider downloading a precompiled binary - `"bin\tio64.exe"` (Windows) or `"bin\tio64"`(Linux).

Regardless of how you invoke `tio-cli` the first time it will prompt you for your Tenable.IO access/secret keys.  `tio-cli` stores these credentils in the `"$HOMEDIR\.tio-cli.yaml"` file.  On Windows that will be something like `"C:\Users\Username\.tio-cli.yaml"` or `"/home/username/.tio-cli.yaml"` on Linux.

You'll need to generate these keys after you log into the [Tenable.IO portal](https://cloud.tenable.com/):

![Generate Keys from Tenable.IO](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/GenerateKeys.gif)

Once you've entered valid keys `tio-cli` will then attempt to execute your actions against the Tenable.IO instance.
```
   $ go run tio.go scans
```
![Input keys into tio-cli](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/tiokeys.png)

## Command Cheat Sheet
**Afer executing commands a new a folder (`--cacheFolder`) will exists with results retrieved from Tenable.IO.**

**By default ("`--useCryptoCache=true`") `tio-cli` encrypts the contents, but the decryption key is in the `"$HOMEDIR\.tio-cli.yaml"` file.  Deleting the 'cacheKey' makes the entire cache permanently inaccessible.**

`tio-cli` supports scans, hosts, history, and cache commands. 

```
   ##Scans
   $ go run tio.go scans
   $ go run tio.go scans --scandid 1,2  
   $ go run tio.go scans --scandid 1,2 --detail
   $ go run tio.go scans --nocolour --quiet
   $ go run tio.go scans --ignoreScan 4,5
   $ go run tio.go scans --ignoreHistory 1003012,100234
   $ go run tio.go scans --useCryptoCache=false --cacheFolder=/opt/cached/

   ##Hosts
   $ go run tio.go hosts --scanid 1,2
   $ go run tio.go hosts --plugin 100424,97833,88906 
   $ go run tio.go hosts --scanid 1,2 --plugin 100424,97833,88906 
   $ go run tio.go hosts --scanid 1,2 --plugin 100424,97833,88906  --previous 1
   
   ##History
   $ go run tio.go history --plugin 100424 
   $ go run tio.go history --plugin 100424 --depth 4
   
   ##Cache
   $ go run tio.go cache
   $ go run tio.go cache --warn
   $ go run tio.go cache --decrypt
   $ go run tio.go cache --decrypt --pretty --output /opt/cache.dec
   $ go run tio.go cache --decrypt --cacheFolder=/home/usr/tio-cli/cache --pretty --output /opt/cache.dec   
   $ go run tio.go cache --encrypt --cacheFolder=/opt/cache.dec --output /opt/cache.enc
```
## go run tio.go scans
The most basic command is just 'scans':

```$ go run tio.go scans```

You can add '`--scanid`' and '`--detail`' for a more specific output:

```$ go run tio.go scans --scanid 1,2 --detail```

![Scan details tio-cli](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/scandetails.png)

## 'Bad' historical scans
You may have some bad historicals scans in your Tenable.IO repository.  I've worked with Tenable.IO technical support and there is currently no way to delete historical scans from Tenable.IO (despite the documentation.) Some symptoms of 'bad' historical data are scans details failing to parse entirely and scans that ONLY EVER return 20 hosts IDs.

![Scan details tio-cli](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/cache.missinghosts.png)

Depending on when your scans run and when Tenable.IO was updated you may notice inconsistencies.  Because of this challenge I've added `--ignoreScan` and `--ignoreHistory` parameters.  Add these to `scans|hosts|history` commands to skip over these bad scans.
```
  ##Ignore entire scans
  $ go run tio.go scans --ignoreScans 3,4,5
  ##Ignore a historical scan of a specific scan
  $ go run tio.go scans --scanid 7 --ignoreHistory 1001123
```

### go run tio.go hosts
`tio-cli` provides a way to output to CSV all hosts from a given scan. Additionally, you can filter to only hosts that matched a given pluging (`--plugin`). 
```
  ##All hosts filtered by scans
  $ go run tio.go hosts --scanid 1,2
  ##All hosts matching at least one plugin
  $ go run tio.go hosts --plugins 100424,97833,88906 
  ##All hosts from scans 1&2 that match any plugin 100424,97833,88906 
  $ go run tio.go hosts --scanid 1,2 --plugins 100424,97833,88906 
  ##All hosts filtered by scan and plugin, from previous scan [historical - 1]
  $ go run tio.go hosts --scanid 1,2 --plugins 100424,97833,88906  --previous 1
```
For each of the host's in the scan a row with these values will be outputted:
```
ScanID,HistoryId,HostId,ScanName,ScanStart,ScanStartUnix,ScanEnd,ScanEndUnix,ScanDuration,HostScanStart,HostScanStartUnix,HostScanEnd,HostScanEndUnix,HostScanDuration,HostIP,MACAddress,HostName,NetBIOS,OperatingSystem,Critical,High,Medium,Low
```
Furthermore, you can specifiy `"--plugin 100464"` and an additional column (in this case `"Microsoft Windows SMBv1 Multiple Vulnerabilities (100464)"`) is added to the CSV output and any host matching that plugin is listed:
![Host list with plugin](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/hostlist.plugin.png)

If you add multiple plugin ids `"--plugin 100464,84729"` each host that matches either of the plugins will be outputted:
![Host list with many plugins](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/hostlist.pluginmany.png)

### go run tio.go historical
The `tio-cli` historical command shows the first and last detection of a plugin for a host in a given set of scans. This is the header row:
```
ScanId,ScanName,LastRun,DaysSinceLastRun,LastDetect,DaysSinceLastDetect,FirstDetect,DaysSinceFirstDect,HostIP,HostFQDN,HostNetBIOS,HostOperatingSystems,PluginId,VulnerableStatus,DurationStatus,Critical,High,Medium,Low
```

You specify exactly one plugin and it will search all historicals (upto `"--depth"` scans back) for hosts that matched.

![Host list with many plugins](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/history.png)


### go run tio.go cache
All `tio-cli` results are cached and encrypted in the default `'cache/'` folder which effectively gives you a local copy of you scan results.  The `.tio.yaml` contains a `cacheKey` entry to control the AES key for encrypt/decrypt. Using the `tio cache --decrypt --anonymize=false --pretty` mechanism you extract your cached JSON pretty printed through the `jq` processor. `tio-cli` will tell you what it has cached with: 

```   $ go run tio.go cache --scanid 76```

![tio-cli cache details](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/cache.png)

**NOTE**: You can delete the `cacheFolder` and `tio-cli` will recreate it as needed with the results from it's queries.

# $HOMEDIR\.tio-cli.yaml
This is `Yet Another Markup Language` configuration for `tio-cli`. It's a really simple file format and any command line parameters you use frequently can put here thanks to Viper and Corba.  For example, if you always wanted `--quiet` mode and to only ever shows scans `--scanid 1,2,3` you could add this to `"$HOMEDIR\.tio-cli.yaml"`:
```
   accessKey: [YOUR_ACCESS_KEY]
   secretKey: [YOUR_SECRET_KEY]
   cacheKey: [YOUR_CACHE_KEY]
   cacheFolder: ./cache/
   tzDefault: -0600 CST
   scanid: 1,2,3
   quiet: true
```

# JSON and golang
This v0.1 implementation is based off of the details posted at https://cloud.tenable.com/api/ - which are mostly accurate.  There are inconsistencies between the published documentation and the JSON actually returned by the call.  At the end of the day `tio-cli` has successfully navigated these inconsistencies. :- )

Some of JSON structures detailed - like hosts,scans,scan details - have been implemeted here using golang's built-in JSON data types.  Golang can natively marshall/unmarshall JSON off the wire which means you create the struct and golang worries about reading/writing it.  Only what's used in `tio-cli` has actually been created in golang.

The Tenable.IO [JSON specification](https://cloud.tenable.com/api#/resources/plugins/plugin-details) look like this:

![tio-cli scans output](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/tenableplugin.jsonspec.png)

From the `tio-cli` created golang structs that can work with it:

![tio-cli scans output](https://github.com/whereiskurt/tio-cli/blob/master/docs/gifs/tenableplugin.gostruct.png)

**NOTE**: Tenable.IO does not have a version number for the vulnerability API and has changed formats at least once in 2017.

# Motivation
I started `tio-cli` in July 2017 because I wanted a command line way to answer questions I was dealing wtih daily, like: 

1. For all current scans show me all the hosts that are vulnerable to plugin 12345
2. For scans X,Y,Z, over the last N scan runs, show me all hosts that are/were
   vulnerable to plugin 12345 with their first/last detection dates.
3. What are all of the detected operating systems for all of the current scans?
4. What are all the IP addresses, hostname/netbois, MAC and OS 
   for all hosts from all scans?

While the Tenable.IO web portal is truly great - I additionally wanted to be able to dump results to CSV files to share easily with my colleagues.  I wanted something that could be scripted to answer questions repeatedly without my oversight.  

To be 100% clear: **THIS IS PROOF OF CONCEPT CODE** (I think I mentioned that above...)  The code has now reach 'maximum spaghetti mess (of love)' and needs to be refactored into well thought-out modules (perhaps to be re-written as v1.0?!) This is mostly because I hastly wrote golang code as I explored ideas like concurrency, JSON types, terminal colouring, etc.  This should all be obvious when you realise there is **no test suite**, **no documentation** in the code and **not even a design overview.**  

OK. This was a lot of fun and I learned a lot (about a lot of topics!) Now I'm sharing because sharing is caring. :- )

KPH
