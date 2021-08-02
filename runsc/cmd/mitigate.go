// Copyright 2021 The gVisor Authors.
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

package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/mitigate"
)

const (
	// cpuInfo is the path used to parse CPU info.
	cpuInfo = "/proc/cpuinfo"
	// Path to shutdown a CPU.
	smtPath = "/sys/devices/system/cpu/smt/control"
)

// Mitigate implements subcommands.Command for the "mitigate" command.
type Mitigate struct {
	// Run the command without changing the underlying system.
	dryRun bool
	// Reverse mitigate by turning on all CPU cores.
	reverse bool
	// Extra data for post mitigate operations.
	data string
}

// Name implements subcommands.command.name.
func (*Mitigate) Name() string {
	return "mitigate"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Mitigate) Synopsis() string {
	return "mitigate mitigates the underlying system against side channel attacks"
}

// Usage implements Usage for cmd.Mitigate.
func (m Mitigate) Usage() string {
	return fmt.Sprintf(`mitigate [flags]

mitigate mitigates a system to the "MDS" vulnerability by writing "off" to /sys/devices/system/cpu/smt/control. CPUs can be restored by writing "on" to the same file or rebooting your system.

The command can be reversed with --reverse, which writes "off" to the file above.%s`, m.usage())
}

// SetFlags sets flags for the command Mitigate.
func (m *Mitigate) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&m.dryRun, "dryrun", false, "run the command without changing system")
	f.BoolVar(&m.reverse, "reverse", false, "reverse mitigate by enabling all CPUs")
	m.setFlags(f)
}

// Execute implements subcommands.Command.Execute.
func (m *Mitigate) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if runtime.GOARCH == "arm64" || runtime.GOARCH == "arm" {
		log.Warningf("As ARM is not affected by MDS, mitigate does not support")
		return subcommands.ExitFailure
	}

	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	return m.doExecute(cpuInfo, smtPath)
}

func (m *Mitigate) doExecute(cpuInfoPath, smtFilePath string) subcommands.ExitStatus {
	beforeSet, err := getCPUSet(cpuInfoPath)
	if err != nil {
		return Errorf("Get before CPUSet failed: %v", err)
	}
	log.Infof("CPUs before: %s", beforeSet.String())

	action := doMitigate
	if m.reverse {
		action = doReverse
	}

	// dryRun should skip any mitigate action.
	if m.dryRun {
		action = func(_ string, _ mitigate.CPUSet) error {
			return nil
		}
	}

	if err := action(smtFilePath, beforeSet); err != nil {
		return Errorf("Action failed: %v", err)
	}
	afterSet, err := getCPUSet(cpuInfoPath)
	if err != nil {
		return Errorf("Get after CPUSet failed: %v", err)
	}
	log.Infof("CPUs after: %s", afterSet.String())

	if err = m.postMitigate(afterSet); err != nil {
		return Errorf("Post Mitigate failed: %v", err)
	}

	return subcommands.ExitSuccess
}

// getCPUSet gets the current CPUSet and prints it.
func getCPUSet(path string) (mitigate.CPUSet, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return mitigate.NewCPUSet(string(data))
}

// doMitigate turns off SMT by writing "off" to /sys/devices/cpu/smt/control.
func doMitigate(filePath string, cpuSet mitigate.CPUSet) error {
	if !cpuSet.IsVulnerable() {
		return nil
	}
	if err := doEnableDisable(filePath, "off"); err != nil {
		return fmt.Errorf("disable: %v", err)
	}
	return nil
}

// doReverse turns on the SMT by writing "on" to /sys/devices/cpu/smt/control.
func doReverse(filePath string, _ mitigate.CPUSet) error {
	if err := doEnableDisable(filePath, "on"); err != nil {
		return fmt.Errorf("enable: %v", err)
	}
	return nil
}

func doEnableDisable(filePath, action string) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", smtPath, err)
	}
	if _, err = f.Write([]byte(action)); err != nil {
		return fmt.Errorf("failed to write \"%s\" to %s: %v", action, smtPath, err)
	}
	return nil
}
