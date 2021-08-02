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

//go:build amd64
// +build amd64

package cmd

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/mitigate/mock"
)

type executeTestCase struct {
	name                   string
	mitigateData           string
	mitigateError          subcommands.ExitStatus
	mitigateExpectedOutput string
	reverseData            string
	reverseError           subcommands.ExitStatus
	reverseExpectedOutput  string
}

func TestExecute(t *testing.T) {

	partial := `processor       : 1
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 49
model name      : AMD EPYC 7B12
physical id     : 0
bugs         : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
power management:
`

	for _, tc := range []executeTestCase{
		{
			name:                   "CascadeLake4",
			mitigateData:           mock.CascadeLake4.MakeMitigatedCPUString(),
			mitigateExpectedOutput: "off",
			reverseData:            mock.CascadeLake4.MakeCPUString(),
			reverseExpectedOutput:  "on",
		},
		{
			name:          "Empty",
			mitigateData:  "",
			mitigateError: Errorf(`mitigate operation failed: no cpus found for: ""`),
			reverseData:   "somethingNotCPU",
			reverseError:  Errorf(`mitigate operation failed: no cpus found for: ""`),
		},
		{
			name: "Partial",
			mitigateData: `processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 49
model name      : AMD EPYC 7B12
physical id     : 0
core id         : 0
cpu cores       : 1
bugs            : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
power management::84

` + partial,
			mitigateError: Errorf(`mitigate operation failed: failed to match key "core id": %q`, partial),
			reverseError:  Errorf(`reverse operation failed: mismatch regex from possible: %q`, "1-"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Mitigate{}
			t.Run("Mitigate", func(t *testing.T) {
				m.doExecuteTest(t, tc.mitigateData, tc.mitigateExpectedOutput, tc.mitigateError)
			})

			if tc.reverseData == "" {
				tc.reverseData = tc.mitigateData
			}
			m.reverse = true
			t.Run("Reverse", func(t *testing.T) {
				m.doExecuteTest(t, tc.reverseData, tc.reverseExpectedOutput, tc.reverseError)
			})
		})
	}
}

// doExecuteTest runs Execute with the mitigate operation and reverse operation.
func (m *Mitigate) doExecuteTest(t *testing.T, data, wantSmt string, wantErr subcommands.ExitStatus) {
	cpuInfo, err := ioutil.TempFile("", "cpuInfo.txt")
	if err != nil {
		t.Fatalf("Failed to create tmpfile: %v", err)
	}
	defer os.Remove(cpuInfo.Name())

	if _, err := cpuInfo.WriteString(data); err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}

	smtFile, err := ioutil.TempFile("", "smt.txt")
	if err != nil {
		t.Fatalf("Failed to create tmpfile: %v", err)
	}
	defer os.Remove(smtFile.Name())

	if _, err := smtFile.WriteString("on"); err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}

	subError := m.doExecute(cpuInfo.Name(), smtFile.Name())
	if subError != wantErr {
		t.Fatalf("Mitigate error mismatch: want: %v got: %v", wantErr, subError)
	}

	// case where test should end in error or we don't care
	// about how many cpus are returned.
	if wantErr != subcommands.ExitSuccess {
		return
	}

	got, err := ioutil.ReadFile(smtFile.Name())
	if err != nil {
		t.Fatalf("Failed to read to file: %v", err)
	}

	if string(got) != wantSmt {
		t.Fatalf("Want smt file: want %s got: %s", wantSmt, got)
	}
}
