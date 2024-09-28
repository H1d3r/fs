package Plugins

import (
	"database/sql"
	"fmt"
	"fs/config"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"time"
)

func OracleBruteforce(info *config.ScannerCfg) (tmperr error) {
	if config.NoBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range config.Userdict["oracle"] {
		for _, pass := range config.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := OracleConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] oracle %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				config.LogError(errlog)
				tmperr = err
				if config.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(config.Userdict["oracle"])*len(config.Passwords)) * config.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func OracleConn(info *config.ScannerCfg, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", Username, Password, Host, Port)
	db, err := sql.Open("oracle", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(config.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(config.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] oracle %v:%v:%v %v", Host, Port, Username, Password)
			config.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
