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
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	pb "github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// NewCmdDryPull creates a new cobra.Command for the repos subcommand.
func NewCmdDryPull(options *[]crane.Option) *cobra.Command {
	var input string
	var output string
	dumpCmd := cobra.Command{
		Use:   "drypull",
		Short: "Dry run image pulling of given images",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigs
				os.Exit(0)
			}()

			if input == "" {
				return fmt.Errorf("input file is required")
			}

			file, err := os.OpenFile(input, os.O_RDONLY, 0644)
			if err != nil {
				return fmt.Errorf("opening file %s: %w", input, err)
			}
			defer file.Close()

			w := bufio.NewWriter(os.Stdout)
			if output != "" {
				outfile, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("failed to open output file %s: %w", output, err)
				}

				defer outfile.Close()
				w = bufio.NewWriter(outfile)
			}
			defer w.Flush()
			logs.InitFile(w)

			pbar := pb.Default(-1, "Drypulling")
			scanner := bufio.NewScanner(file)

			input := make(chan string, 100)
			wg := sync.WaitGroup{}
			layers := map[string]bool{}
			maplock := sync.Mutex{}
			for i := 0; i < 20; i++ {
				go startPulling(&wg, &layers, &maplock, w, input, options)
			}

			for scanner.Scan() {
				pbar.Add(1)
				line := scanner.Text()
				if line == "" {
					continue
				}

				wg.Add(1)
				input <- line
			}

			close(input)
			wg.Wait()
			pbar.Finish()
			return nil
		},
	}

	dumpCmd.Flags().StringVar(&input, "input", "", "Input file with list of images to dump")
	dumpCmd.Flags().StringVar(&output, "output", "", "Output file to dump")

	return &dumpCmd
}

func startPulling(wg *sync.WaitGroup, layers *map[string]bool, maplock *sync.Mutex, w *bufio.Writer, input <-chan string, options *[]crane.Option) {
	for image := range input {
		if err := drypullImage(w, layers, maplock, image, options); err != nil {
			fmt.Printf("Failed drypulling image %s: %s\n", image, err)
		}
		wg.Done()
	}
}

func drypullImage(w *bufio.Writer, layers *map[string]bool, maplock *sync.Mutex, image string, options *[]crane.Option) error {
	o := crane.GetOptions(*options...)
	src := image

	logs.Debug.Printf("drypulling %s", src)
	ref, err := name.ParseReference(src)
	if err != nil {
		return fmt.Errorf("parsing reference %q: %w", src, err)
	}

	rmt, err := remote.Get(ref, o.Remote...)
	if err != nil {
		return err
	}

	img, err := rmt.Image()
	if err != nil {
		return err
	}

	digest, err := img.Digest()
	if err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("unable to get manifest for img %s: %w", src, err)
	}

	maplock.Lock()
	defer maplock.Unlock()
	path := fmt.Sprintf("docker/registry/v2/blobs/sha256/%s/%s", manifest.Config.Digest.Hex[:2], manifest.Config.Digest.Hex)
	w.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", image, manifest.Config.Digest.Hex, manifest.Config.Digest.Hex, path))

	path = fmt.Sprintf("docker/registry/v2/blobs/sha256/%s/%s", digest.Hex[:2], digest.Hex)
	w.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", image, digest.Hex, digest.Hex, path))
	for _, l := range manifest.Layers {
		if _, ok := (*layers)[l.Digest.String()]; ok {
			continue
		}
		(*layers)[l.Digest.String()] = true
		path := fmt.Sprintf("docker/registry/v2/blobs/sha256/%s/%s", l.Digest.Hex[:2], l.Digest.Hex)
		w.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", image, digest.Hex, l.Digest.Hex, path))
	}
	w.Flush()

	return nil
}

func calculateSingleFileInTarSize(in int64) (out int64) {
	// doing this manually, because math.Round() works with float64
	out += in
	if remainder := out % 512; remainder != 0 {
		out += (512 - remainder)
	}
	out += 512
	return out
}
