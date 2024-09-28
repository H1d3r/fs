package Plugins

import (
	"fmt"
	"fs/config"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Addr struct {
	ip   string
	port int
}

func PortConnect(addr Addr, repHostsChan chan<- string, adjustedTimeout int64, wg *sync.WaitGroup) {
	host, port := addr.ip, addr.port
	conn, err := config.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	if err == nil {
		defer conn.Close()
		address := host + ":" + strconv.Itoa(port)
		wg.Add(1)
		repHostsChan <- address
	}
}

// parsePorts 函数解析端口字符串，返回一个整数切片
func parsePorts(portStr string) ([]int, error) {
	var ports []int
	for _, portRange := range strings.Split(portStr, "|") {
		if strings.Contains(portRange, ",") {
			// 逗号分隔的列表
			for _, port := range strings.Split(portRange, ",") {
				p, err := strconv.Atoi(port)
				if err != nil {
					return nil, err
				}
				ports = append(ports, p)
			}
		} else if strings.Contains(portRange, "-") {
			// 端口范围
			rangeParts := strings.Split(portRange, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", portRange)
			}
			startPort, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, err
			}
			endPort, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, err
			}
			for i := startPort; i <= endPort; i++ {
				ports = append(ports, i)
			}
		} else {
			// 单个端口
			p, err := strconv.Atoi(portRange)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	ports = config.RemoveDuplicate(ports)
	sort.Ints(ports)

	return ports, nil
}

func PortScan(aliveHosts []string, ports string, timeout int64) []string {
	var aliveAddress []string
	scanPorts, _ := parsePorts(ports)

	workers := config.Threads
	AddrsChan := make(chan Addr, 100)
	resultsChan := make(chan string, 100)
	var portScanWG sync.WaitGroup

	// 接收结果
	go func() {
		for found := range resultsChan {
			aliveAddress = append(aliveAddress, found)
			portScanWG.Done()
		}
	}()

	// 消费者 - 多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range AddrsChan {
				PortConnect(addr, resultsChan, timeout, &portScanWG)
				portScanWG.Done()
			}
		}()
	}

	// 生产者 - 添加扫描目标
	for _, host := range aliveHosts {
		for _, port := range scanPorts {
			portScanWG.Add(1)
			AddrsChan <- Addr{host, port}
		}
	}

	portScanWG.Wait()
	config.MapIPToPorts(aliveAddress)
	close(AddrsChan)
	close(resultsChan)
	return aliveAddress
}

func NoPortScan(aliveHosts []string, ports string) (AliveAddress []string) {
	Ports, _ := parsePorts(ports)
	for _, port := range Ports {
		for _, host := range aliveHosts {
			address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, address)
		}
	}
	return
}
