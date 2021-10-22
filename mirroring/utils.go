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

package mirroring

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// ReadLogInfo reads and loads the latest monitored log's tree size
// and root hash from the specified text file.
func ReadLogInfo(filename string) (int64, string, error) {
	// Each line in the file is one snapshot data of the log
	file, err := os.Open(filename)
	if err != nil {
		return 0, "", err
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
	treeSize, err := strconv.ParseInt(parsed[0], 10, 64)
	if err != nil {
		return 0, "", err
	}
	root := parsed[1]

	if err := scanner.Err(); err != nil {
		return 0, "", err
	}
	return treeSize, root, nil
}
