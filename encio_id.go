//go:build !linux

package encio

import "github.com/denisbrodbeck/machineid"

var machineIDFn = machineid.ProtectedID
