// Copyright 2019 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	pb "github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// NewCmdDumpTags creates a new cobra.Command for the repos subcommand.
func NewCmdDumpTags(options *[]crane.Option) *cobra.Command {
	var input string
	var output string
	dumpCmd := cobra.Command{
		Use:   "dumptags",
		Short: "Dump all image tags of entire repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			reg := args[0]
			fmt.Printf("Dumping registry %s\n", reg)

			var repos []string
			if input != "" {
				rows, err := ioutil.ReadFile(input)
				if err != nil {
					return fmt.Errorf("failed to read input file %s: %w", input, err)
				}
				repos = strings.Split(string(rows), "\n")
			} else {
				r, err := crane.Catalog(reg, *options...)
				if err != nil {
					return fmt.Errorf("reading repos for %s: %w", reg, err)
				}
				repos = r
			}

			w := bufio.NewWriter(os.Stdout)
			if output != "" {
				outfile, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("failed to open output file %s: %w", output, err)
				}

				defer outfile.Close()
				w = bufio.NewWriter(outfile)
			}

			pbar := pb.Default(int64(len(repos)))
			fmt.Printf("Enumerate %d repos\n", len(repos))
			for _, repo := range repos {
				pbar.Add(1)
				tags, err := crane.ListTags(fmt.Sprintf("%s/%s", reg, repo), *options...)
				if err != nil {
					fmt.Printf("[FAILED] Reading tags for %s: %s\n", repo, err)
					continue
				}
				for _, tag := range tags {
					w.WriteString(fmt.Sprintf("%s,%s,%s\n", reg, repo, tag))
				}
				if err := w.Flush(); err != nil {
					return fmt.Errorf("flushing output: %w", err)
				}
			}
			return nil
		},
	}

	dumpCmd.Flags().StringVar(&input, "input", "", "Input file with list of images to dump")
	dumpCmd.Flags().StringVar(&output, "output", "", "Output file to dump")

	return &dumpCmd
}
