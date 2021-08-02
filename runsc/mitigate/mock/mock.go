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

// Package mock contains mock CPUs for mitigate tests.
package mock

import "fmt"

// CPU represents data from CPUs that will be mitigated.
type CPU struct {
	Name           string
	VendorID       string
	Family         int
	Model          int
	ModelName      string
	Bugs           string
	PhysicalCores  int
	Cores          int
	ThreadsPerCore int
	IsVulnerable   bool
}

// CascadeLake2 is a two core Intel CascadeLake machine.
var CascadeLake2 = CPU{
	Name:           "CascadeLake",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          85,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa",
	PhysicalCores:  1,
	Cores:          1,
	ThreadsPerCore: 2,
	IsVulnerable:   true,
}

// CascadeLake4 is a four core Intel CascadeLake machine.
var CascadeLake4 = CPU{
	Name:           "CascadeLake",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          85,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa",
	PhysicalCores:  1,
	Cores:          2,
	ThreadsPerCore: 2,
	IsVulnerable:   true,
}

// Haswell2 is a two core Intel Haswell machine.
var Haswell2 = CPU{
	Name:           "Haswell",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          63,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs",
	PhysicalCores:  1,
	Cores:          1,
	ThreadsPerCore: 2,
	IsVulnerable:   true,
}

// Haswell2core is a 2 core Intel Haswell machine with no hyperthread pairs.
var Haswell2core = CPU{
	Name:           "Haswell2Physical",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          63,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs",
	PhysicalCores:  2,
	Cores:          1,
	ThreadsPerCore: 1,
	IsVulnerable:   true,
}

// AMD2 is an two core AMD machine.
var AMD2 = CPU{
	Name:           "AMD",
	VendorID:       "AuthenticAMD",
	Family:         23,
	Model:          49,
	ModelName:      "AMD EPYC 7B12",
	Bugs:           "sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass",
	PhysicalCores:  1,
	Cores:          1,
	ThreadsPerCore: 2,
}

// AMD8 is an eight core AMD machine.
var AMD8 = CPU{
	Name:           "AMD",
	VendorID:       "AuthenticAMD",
	Family:         23,
	Model:          49,
	ModelName:      "AMD EPYC 7B12",
	Bugs:           "sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass",
	PhysicalCores:  4,
	Cores:          1,
	ThreadsPerCore: 2,
}

// MakeCPUString makes a string formated like /proc/cpuinfo for each cpuTestCase
func (tc CPU) MakeCPUString() string {
	return tc.doMakeCPUString(tc.PhysicalCores, tc.Cores, tc.ThreadsPerCore)
}

// MakeMitigatedCPUString returns a /proc/cpuinfo for the machine assuming a mitigate function was successful.
func (tc CPU) MakeMitigatedCPUString() string {
	if tc.IsVulnerable {
		return tc.doMakeCPUString(tc.PhysicalCores, tc.Cores, 1 /*ThreadsPerCore*/)
	}
	return tc.MakeCPUString()
}

func (tc CPU) doMakeCPUString(physicalCores, cores, threadsPerCore int) string {
	template := `processor	: %d
vendor_id	: %s
cpu family	: %d
model		: %d
model name	: %s
physical id  : %d
core id		: %d
cpu cores	: %d
bugs		: %s

`

	ret := ``
	for i := 0; i < physicalCores; i++ {
		for j := 0; j < cores; j++ {
			for k := 0; k < threadsPerCore; k++ {
				processorNum := (i*cores+j)*threadsPerCore + k
				ret += fmt.Sprintf(template,
					processorNum, /*processor*/
					tc.VendorID,  /*vendor_id*/
					tc.Family,    /*cpu family*/
					tc.Model,     /*model*/
					tc.ModelName, /*model name*/
					i,            /*physical id*/
					j,            /*core id*/
					k,            /*cpu cores*/
					tc.Bugs,      /*bugs*/
				)
			}
		}
	}
	return ret
}

// NumCPUs returns the number of CPUs for this CPU.
func (tc CPU) NumCPUs() int {
	return tc.PhysicalCores * tc.Cores * tc.ThreadsPerCore
}
