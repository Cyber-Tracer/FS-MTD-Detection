package main

import (
	"fmt"
	"math"
	"os"
	"strings"
	"strconv"
)

var blockList []string
var allowList []string

func isBlocklisted(pid uint32) bool {
	pidToCheck := strconv.FormatUint(uint64(pid), 10)
	for _, v := range blockList {
		if v == pidToCheck {
			return true
		}
	}
	return false
}

func isAllowlisted(pid uint32) bool {
	pidToCheck := strconv.FormatUint(uint64(pid), 10)
	for _, v := range allowList {
		if v == pidToCheck {
			return true
		}
	}
	return false
}

func registerPid(pid uint32, malicious bool) {
	pidToCheck := strconv.FormatUint(uint64(pid), 10)

	if !isBlocklisted(pid) && malicious {
		blockList = append(blockList, pidToCheck)
	}

	if !isBlocklisted(pid) && !isAllowlisted(pid) {
		// USE only blocklist
		//allowList = append(allowList, pidToCheck)
	}
}


func isMalicious(pid uint32) bool {
	classifier, err := os.ReadFile("../logs/classifier.log")
	if err != nil {
		fmt.Println(err)
	}
	//classification := strconv.FormatUint(uint64(classifier), 10)
	classification := string(classifier)
	pids := strings.Split(classification, "\n")

	requestingProcess := strconv.FormatUint(uint64(pid), 10)
	fmt.Printf("\nIs %s malicious?\n", requestingProcess)
	fmt.Printf("Received %s from classifier..\n", classification)

	malicious := false
	for i := 0; i < len(pids); i++ {
		if pids[i] == requestingProcess {
			malicious = true
		}
	}
	if malicious {
		fmt.Printf("Malicious!")
		//cmd := exec.Command("kill", requestingProcess)

                // The `Output` method executes the command and
                // collects the output, returning its value
                //out, _ := cmd.Output()
                //fmt.Println(out)
	} else {
		fmt.Printf("Benign..")
	}
	registerPid(pid, malicious)

	return malicious
}


// This is a Go re-implementation of entropy calculation from the following page: 
// https://cocomelonc.github.io/malware/2022/11/05/malware-analysis-6.html
func GetEntropy(data []byte) (entr float64) {
	possible := make(map[string]int)

	for i := 1; i <= 256; i++ {
		possible[string(i)] = 0
	}

	for _, byt := range data {
		possible[string(byt)] += 1
	}

	var data_len = len(data)
	var entropy = 0.0

	for char := range possible {
		if possible[char] == 0 {
			continue
		}
		var p = float64(possible[char]) / float64(data_len)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
