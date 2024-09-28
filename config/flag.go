package config

import (
	"fmt"
	"github.com/projectdiscovery/goflags"
)

type ScannerCfg struct {
	Host      string
	Ports     string
	HostsFile string
	PortsFile string
	Url       string
	UrlsFIle  string
	InfoStr   []string
}

type PocInfo struct {
	Target  string
	PocName string
}

var (
	ScanPorts    string
	Path         string
	Scantype     string
	Command      string
	SshKey       string
	Domain       string
	Username     string
	Password     string
	Proxy        string
	Timeout      int64 = 3
	WebTimeout   int64 = 5
	TmpSave      bool
	NoPing       bool
	PingScanType bool
	Pocinfo      PocInfo
	NoPoc        bool
	NoBrute      bool
	RedisFile    string
	RedisShell   string
	Userfile     string
	Passfile     string
	HostFile     string
	PortFile     string
	PocPath      string
	Threads      = 600
	URL          string
	UrlFile      string
	Urls         []string
	NoPorts      string
	NoHosts      string
	SC           string
	PortAdd      string
	UserAdd      string
	PassAdd      string
	BruteThread  int
	LiveTop      int
	Socks5Proxy  string
	Hash         string
	HashBytes    []byte
	HostPort     []string
	IsWmi        bool
	Noredistest  bool
	Outputfile   string
)

func Banner() {
	fmt.Printf("[*] fs Tools version %s, Modified from fscan, Powered P001water\n\n", version)
}

func Flag(Info *ScannerCfg) {
	Banner()
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("P001water二开的fscan, 仅供技术交流使用,切勿用于非法途径")
	flagSet.CreateGroup("Usage", "basicScanUsage",
		flagSet.StringVar(&Info.Host, "t", "", "IP input format, eg: 192.168.11.11|192.168.11.11-255|192.168.11.11,192.168.11.12"),
		flagSet.StringVar(&HostFile, "tf", "", "host file, -hf ip.txt"),
		flagSet.StringVar(&NoHosts, "tn", "", "IP no scan,eg: -hn 192.168.1.1/24"),
		flagSet.StringVar(&URL, "u", "", "url"),
		flagSet.StringVar(&UrlFile, "uf", "", "urlfile"),
		flagSet.StringVar(&ScanPorts, "p", DefaultPorts, "ScanPort input format. eg: 22|1-65535|22,80,3306"),
		flagSet.StringVar(&PortFile, "pf", "", "Port File"),
		flagSet.StringVar(&PortAdd, "pa", "", "add port base DefaultPorts,-pa 3389"),
		flagSet.StringVar(&NoPorts, "pn", "", "the ports no scan,as: -pn 445"),
		flagSet.BoolVar(&NoPing, "np", false, "no ping"),
		flagSet.BoolVar(&PingScanType, "ping", false, "icmp use false, ping use true"),
	)

	flagSet.CreateGroup("proxy", "proxyConfig",
		flagSet.StringVar(&Proxy, "proxy", "", "set poc proxy, -proxy http://127.0.0.1:8080"),
		flagSet.StringVar(&Socks5Proxy, "socks5", "", "set socks5 proxy, will be used in tcp connection, timeout setting will not work"),
	)

	flagSet.CreateGroup("fileConfig", "fileConfig",
		flagSet.StringVar(&Username, "user", "", "username"),
		flagSet.StringVar(&Password, "pwd", "", "password"),
		flagSet.StringVar(&Userfile, "userf", "", "username file"),
		flagSet.StringVar(&Passfile, "pwdf", "", "password file"),
	)

	flagSet.CreateGroup("plugins", "plugins",
		flagSet.StringVar(&Command, "c", "", "exec command (ssh|wmiexec)"),
		flagSet.StringVar(&SshKey, "sshkey", "", "sshkey file (id_rsa)"),
		flagSet.StringVar(&UserAdd, "usera", "", "add a user base DefaultUsers,-usera user"),
		flagSet.StringVar(&PassAdd, "pwda", "", "add a password base DefaultPasses,-pwda password"),
		flagSet.StringVar(&Domain, "domain", "", "smb domain"),
		flagSet.StringVar(&Scantype, "m", "all", "Select scan type ,as: -m ssh"),
		flagSet.StringVar(&Path, "path", "", "fcgi、smb romote file path"),
		//flagSet.IntVar(&Threads, "t", 600, "Thread nums"),
		flagSet.IntVar(&LiveTop, "top", 10, "show live len top"),
		flagSet.StringVar(&PocPath, "pocpath", "", "poc file path"),
		flagSet.StringVar(&RedisFile, "rf", "", "redis file to write sshkey file (as: -rf id_rsa.pub)"),
		flagSet.StringVar(&RedisShell, "rs", "", "redis shell to write cron file (as: -rs 192.168.1.1:6666)"),
		flagSet.BoolVar(&NoPoc, "nopoc", false, "not to scan web vul"),
		flagSet.BoolVar(&NoBrute, "nobr", false, "not to Brute password"),
		flagSet.IntVar(&BruteThread, "br", 1, "Brute threads"),
		flagSet.StringVar(&Outputfile, "o", "r.txt", "Outputfile"),
		flagSet.BoolVar(&TmpSave, "no", false, "not to save output log"),
		//flagSet.IntVar(&WaitTime, "debug", 60, "every time to LogErr"),
		flagSet.BoolVar(&Silent, "silent", false, "silent scan"),
		flagSet.BoolVar(&Nocolor, "nocolor", false, "no color"),
		flagSet.BoolVar(&PocFull, "full", false, "poc full scan,as: shiro 100 key"),
		flagSet.StringVar(&Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, -pocname weblogic"),
		flagSet.StringVar(&Cookie, "cookie", "", "set poc cookie,-cookie rememberMe=login"),
		flagSet.BoolVar(&DnsLog, "dns", false, "using dnslog poc"),
		flagSet.IntVar(&PocNum, "num", 20, "poc rate"),
		flagSet.StringVar(&SC, "sc", "", "-sc add"),
		flagSet.BoolVar(&IsWmi, "wmi", false, "start wmi"),
		flagSet.StringVar(&Hash, "hash", "", "hash"),
		flagSet.BoolVar(&Noredistest, "noredis", false, "no redis sec test"),
	)
	err := flagSet.Parse()
	if err != nil {
		return
	}
}
