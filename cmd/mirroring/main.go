//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"database/sql"

	// "encoding/json"
	// "encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/mirroring"
	"github.com/sigstore/rekor/pkg/client"
)

// Default values for mirroring job parameters
const (
	publicRekorServerURL = "https://api.sigstore.dev"
	logInfoFileName      = "logInfo.txt"
)

// type dataRow struct {
// 	ID      int64
// 	payload string
// }

type Payload struct {
	Attestation     string `json:"Attestation"`
	AttestationType string `json:"AttestationType"`
	Body            Body   `json:"Body"`
	LogIndex        int64  `json:"LogIndex"`
	IntegratedTime  int64  `json:"IntegratedTime"`
	UUID            string `json:"UUID"`
	LogID           string `json:"LogID"`
}

type Body struct {
	RekordObj RekordObj `json:"RekordObj"`
}

type RekordObj struct {
	Data      Data      `json:"data"`
	Signature Signature `json:"signature"`
}

type Data struct {
	Hash Hash `json:"hash"`
}

type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type Signature struct {
	Content   string    `json:"content"`
	Format    string    `json:"format"`
	PublicKey PublicKey `json:"publicKey"`
}

type PublicKey struct {
	Content string `json:"content"`
}

// readLogInfo reads and loads the latest monitored log's tree size
// and root hash from the specified text file.
func readLogInfo(treeSize *int64, root *string) error {
	// Each line in the file is one snapshot data of the log
	file, err := os.Open(logInfoFileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read line by line and get the last line
	scanner := bufio.NewScanner(file)
	line := ""
	for scanner.Scan() {
		line = scanner.Text()
	}

	// Each line is in the format of space-separeted info: "treeSize rootHash"
	parsed := strings.Split(line, " ")
	*treeSize, err = strconv.ParseInt(parsed[0], 10, 64)
	if err != nil {
		return err
	}
	*root = parsed[1]

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// This main function performs a periodic root hash consistency check.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform consistency check for every time interval that was specified.
func main() {
	// Command-line flags that are parameters to the mirroring job
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	interval := flag.Int64("interval", 5, "Length of interval between each periodical consistency check")
	logInfoFile := flag.String("file", logInfoFileName, "Name of the file containing initial merkle tree information")
	flag.Parse()

	// Initialize system logger
	// syslogger, err := syslog.New(syslog.LOG_INFO, "rekor-monitor")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.SetOutput(syslogger)

	// Initialize a rekor client
	rekorClient, err := client.GetRekorClient(*serverURL)
	if err != nil {
		log.Fatal(err)
	}

	// Load any existing latest signed tree head information
	var treeSize int64
	var root string
	var first bool

	if _, err := os.Stat(*logInfoFile); err == nil {
		// File containing old snapshot exists
		err := readLogInfo(&treeSize, &root)
		if err != nil {
			log.Fatal(err)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		// No old snapshot data available: get latest signed tree head and load
		logInfo, err := mirroring.GetLogInfo(rekorClient)
		if err != nil {
			log.Fatal(err)
		}

		pubkey, err := mirroring.GetPublicKey(rekorClient)
		if err != nil {
			log.Fatal(err)
		}

		// Verify the queried signed tree head with server's public key
		err = mirroring.VerifySignedTreeHead(logInfo, pubkey)
		if err != nil {
			log.Fatal(err)
		}

		treeSize = *logInfo.TreeSize
		root = *logInfo.RootHash
		first = true
	} else {
		// Any other errors reading the file
		log.Fatal(err)
	}

	// Open file to create/append new snapshots
	file, err := os.OpenFile(*logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()

	// If this is the very first snapshot within the monitor, save the snapshot
	if first {
		_, err = file.WriteString(fmt.Sprintf("%d %s\n", treeSize, root))
		if err != nil {
			log.Println(err)
		}
	}

	for {
		// Check for root hash consistency
		newTreeSize, newRoot, err := mirroring.VerifyLogConsistency(rekorClient, treeSize, root)
		if err != nil {
			log.Println(err)
		} else {
			log.Printf("Root hash consistency verified - Tree Size: %d Root Hash: %s\n", newTreeSize, newRoot)
		}

		// Append new, consistency-checked snapshots
		if newTreeSize != treeSize {
			_, err = file.WriteString(fmt.Sprintf("%d %s\n", treeSize, root))
			if err != nil {
				log.Println(err)
			}

			treeSize = newTreeSize
			root = newRoot
		}

		database, _ := sql.Open("sqlite3", "./testy.db") //open database
		id, _, err := mirroring.GetLatest(database)
		log.Println("currentLastID: ", id, "newTreeSize: ", newTreeSize)
		if newTreeSize-id != 0 { //last id in our database compared to new tree size
			// mirroring.rows, err = mirroring.getLatestX(database, (newTreeSize - id))
			for i := id + 1; i < newTreeSize; i++ {
				_, payload, _ := mirroring.GetLogEntryByIndex(i, rekorClient)
				// log.Println("payload value: %s", payload.Body.(string))
				// b, _ := base64.StdEncoding.DecodeString(payload.Body.(string))
				pay, _ := payload.MarshalBinary()
				// b, _ := base64.StdEncoding.DecodeString(pay)

				decodeB := string(pay[:])
				log.Println("ID IS: %d", id)
				log.Println("payload value: %s", decodeB)
				// idS := string(id)
				d := mirroring.Data{
					ID:      i,
					Payload: decodeB,
				}
				_, err := mirroring.Insert(database, d)
				if err != nil {
					log.Println("%s\n", err)
				}
				// if rows == -1 {
				// 	log.Println("Expected to get a row insert but instead recieved error")
				// }
			}
		}

		// if err != nil {
		// 	log.Println(err)
		// }
		// if id != 1999 {
		// 	log.Println("Expected Result 1999, instead retrieved %d", id)
		// } else {
		// 	err := json.Unmarshal(stringPay, &payload)

		// 	if err != nil {
		// 		log.Println(err)
		// 	}
		// }

		time.Sleep(time.Duration(*interval) * time.Minute)
	}
}
