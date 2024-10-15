// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsecrps

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/cpumap"
	"github.com/cilium/cilium/pkg/option"
)

func TestConf(t *testing.T) {
	tests := []struct {
		name                    string
		enabled                 bool
		userEnable              bool
		externalXDPMode         xdp.AccelerationMode
		validateExternalXDPMode bool
		enableIPSec             bool
		enableCPUMap            bool
		givesError              bool
	}{
		{
			name:                    "disabled by user with XDP disabled, no IPSec, no cpumap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeDisabled,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP disabled, no IPSec, with cpumap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeDisabled,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            true,
		},
		{
			name:                    "disabled by user with XDP native, no IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeNative,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP native, no IPSec, with CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeNative,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            true,
		},
		{
			name:                    "disabled by user with XDP generic, no IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeGeneric,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP generic, no IPSec, with CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeGeneric,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            true,
		},
		{
			name:                    "disabled by user with XDP best effort, no IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeBestEffort,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP best effort, no IPSec, with CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeBestEffort,
			validateExternalXDPMode: true,
			enableIPSec:             false,
			enableCPUMap:            true,
		},
		{
			name:                    "disabled by user with XDP disabled, IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeDisabled,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP disabled, IPSec, with CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeDisabled,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            true,
		},
		{
			name:                    "disabled by user with XDP native, IPSec, with CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeNative,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            true,
		},
		{
			name:                    "disabled by user with XDP native, IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeNative,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP generic, IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeGeneric,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP generic, IPSec, CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeGeneric,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP best effort, IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeBestEffort,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
		},
		{
			name:                    "disabled by user with XDP best effort, IPSec, CPUMap",
			enabled:                 false,
			userEnable:              false,
			externalXDPMode:         xdp.AccelerationModeBestEffort,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            true,
		},
		{
			name:            "enabled by user with XDP disabled, no IPSec, no CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeDisabled,
			enableIPSec:     false,
			enableCPUMap:    false,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP disabled, no IPSec, with CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeDisabled,
			enableIPSec:     false,
			enableCPUMap:    true,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP native, no IPSec, no CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeNative,
			enableIPSec:     false,
			enableCPUMap:    false,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP native, no IPSec, CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeNative,
			enableIPSec:     false,
			enableCPUMap:    true,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP generic, no IPSec, no CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeGeneric,
			enableIPSec:     false,
			enableCPUMap:    false,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP generic, no IPSec, CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeGeneric,
			enableIPSec:     false,
			enableCPUMap:    true,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP best effort, no IPSec, CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeBestEffort,
			enableIPSec:     false,
			enableCPUMap:    true,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP best effort, no IPSec, no CPUMap",
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeBestEffort,
			enableIPSec:     false,
			enableCPUMap:    false,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP disabled, IPSec, CPUMap",
			enabled:         true,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeDisabled,
			enableIPSec:     true,
			enableCPUMap:    true,
		},
		{
			name:            "enabled by user with XDP disabled, IPSec, no CPUMap",
			enabled:         true,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeDisabled,
			enableIPSec:     true,
			enableCPUMap:    false,
		},
		{
			name:                    "enabled by user with XDP validated to disabled, IPSec, CPUMap",
			userEnable:              true,
			externalXDPMode:         xdp.AccelerationModeDisabled,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            true,
			givesError:              true,
		},
		{
			name:                    "enabled by user with XDP validated to disabled, IPSec, no CPUMap",
			userEnable:              true,
			externalXDPMode:         xdp.AccelerationModeDisabled,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
			givesError:              true,
		},
		{
			name:            "enabled by user with XDP native, IPSec, CPUMap",
			enabled:         true,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeNative,
			enableIPSec:     true,
			enableCPUMap:    true,
		},
		{
			// CPUMap is greedy enabled.
			name:            "enabled by user with XDP native, IPSec, no CPUMap",
			enabled:         true,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeNative,
			enableIPSec:     true,
			enableCPUMap:    false,
		},
		{
			name:            "enabled by user with XDP generic, IPSec, CPUMap",
			enabled:         false,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeGeneric,
			enableIPSec:     true,
			enableCPUMap:    true,
			givesError:      true,
		},
		{
			name:            "enabled by user with XDP generic, IPSec, no CPUMap",
			enabled:         false,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeGeneric,
			enableIPSec:     true,
			enableCPUMap:    false,
			givesError:      true,
		},
		{
			// XDP Native takes precedence over XDP best effort.
			name:            "enabled by user with XDP best effort, IPSec, CPUMap",
			enabled:         true,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeBestEffort,
			enableIPSec:     true,
			enableCPUMap:    true,
		},
		{
			name:            "enabled by user with XDP best effort, IPSec, no CPUMap",
			enabled:         true,
			userEnable:      true,
			externalXDPMode: xdp.AccelerationModeBestEffort,
			enableIPSec:     true,
			enableCPUMap:    false,
		},
		{
			name:                    "enabled by user with XDP validated to best effort, IPSec, CPUMap",
			enabled:                 false,
			userEnable:              true,
			externalXDPMode:         xdp.AccelerationModeBestEffort,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            true,
			givesError:              true,
		},
		{
			name:                    "enabled by user with XDP validated to best effort, IPSec, no CPUMap",
			enabled:                 false,
			userEnable:              true,
			externalXDPMode:         xdp.AccelerationModeBestEffort,
			validateExternalXDPMode: true,
			enableIPSec:             true,
			enableCPUMap:            false,
			givesError:              true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result Config

			err := hive.New(
				xdp.TestCell,
				cpumap.TestConfigCell,
				cell.Provide(
					func() xdp.EnablerOut {
						if test.validateExternalXDPMode {
							return xdp.NewEnabler(
								test.externalXDPMode,
								xdp.WithValidator(
									func(am xdp.AccelerationMode, _ xdp.Mode) error {
										if am != test.externalXDPMode {
											return fmt.Errorf("mode must be %s", test.externalXDPMode)
										}
										return nil
									},
								),
							)
						}
						return xdp.NewEnabler(test.externalXDPMode)
					},
					func() cpumap.EnablerOut {
						return cpumap.NewEnabler(test.enableCPUMap)
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPSec: test.enableIPSec,
						}
					},
					func() userFlags {
						return userFlags{EnableIpsecAcceleration: test.userEnable}
					},
					newUserCfg,
					newConfig,
				),
				cell.Invoke(func(cfg Config) { result = cfg }),
			).Populate(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)))

			if test.givesError {
				if err == nil {
					t.Error("expected error from hive but got nil")
					t.FailNow()
				}
			}

			if test.enabled != result.enabled {
				t.Errorf("expected IPSec RPS to be %t, instead got %t", test.enabled, result.enabled)
			}
		})
	}
}
