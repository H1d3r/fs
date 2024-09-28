package WebScan

import (
	"crypto/md5"
	"fmt"
	"fs/WebScan/info"
	"fs/config"
	"regexp"
)

type CheckDatas struct {
	Body    []byte
	Headers string
}

func InfoCheck(Url string, CheckData *[]CheckDatas) []string {
	var matched bool
	var infoName []string

	for _, data := range *CheckData {
		for _, rule := range info.RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoName = append(infoName, rule.Name)
			}
		}
		//flag, name := CalcMd5(data.Body)

		//if flag == true {
		//	infoName = append(infoName, name)
		//}
	}

	infoName = config.RemoveDuplicate(infoName)

	if len(infoName) > 0 {
		result := fmt.Sprintf("[+] InfoScan %-25v %s ", Url, infoName)
		config.LogSuccess(result)
		return infoName
	}
	return []string{""}
}

func CalcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range info.Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
