// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsecrps

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"ipsec-rps-config",
	"Accelerated IPSec with RPS configuration",

	cell.Config(defaultUserFlags),

	cell.Provide(
		newUserCfg,
		newConfig,

		// Provide datapath options.
		Config.datapathConfigProvider,
	),
)
