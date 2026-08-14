// Package benchmarks contains capacity-planning helpers and CockroachDB-backed
// benchmarks. Estimates consume measured production-like results; they do not
// assert a throughput number for an unmeasured deployment.
package benchmarks

import (
	"errors"
	"math/big"
)

const basisPoints = int64(10000)

type ShardAssumptions struct {
	TargetTPS             int64 `json:"target_tps"`
	MeasuredPerShardTPS   int64 `json:"measured_per_shard_tps"`
	PlannedUtilizationBPS int64 `json:"planned_utilization_bps"`
	SurvivingCapacityBPS  int64 `json:"surviving_capacity_bps"`
}

type ShardEstimate struct {
	TotalShards        int64 `json:"total_shards"`
	PlannedPerShardTPS int64 `json:"planned_per_shard_tps"`
	UsableFleetTPS     int64 `json:"usable_fleet_tps"`
}

// EstimateLedgerShards applies explicit headroom and failure-reserve factors
// to an observed sustainable per-shard rate. All rounding is conservative:
// shard count rounds up and usable capacity rounds down.
func EstimateLedgerShards(input ShardAssumptions) (ShardEstimate, error) {
	if input.TargetTPS <= 0 || input.MeasuredPerShardTPS <= 0 {
		return ShardEstimate{}, errors.New("target and measured per-shard TPS must be positive")
	}
	if input.PlannedUtilizationBPS <= 0 || input.PlannedUtilizationBPS > basisPoints ||
		input.SurvivingCapacityBPS <= 0 || input.SurvivingCapacityBPS > basisPoints {
		return ShardEstimate{}, errors.New("utilization and surviving capacity must be in 1..10000 basis points")
	}

	numerator := new(big.Int).Mul(big.NewInt(input.TargetTPS), big.NewInt(basisPoints*basisPoints))
	denominator := new(big.Int).Mul(big.NewInt(input.MeasuredPerShardTPS), big.NewInt(input.PlannedUtilizationBPS))
	denominator.Mul(denominator, big.NewInt(input.SurvivingCapacityBPS))
	shards := ceilQuotient(numerator, denominator)
	if !shards.IsInt64() {
		return ShardEstimate{}, errors.New("estimated shard count exceeds int64")
	}

	plannedPerShard := new(big.Int).Mul(big.NewInt(input.MeasuredPerShardTPS), big.NewInt(input.PlannedUtilizationBPS))
	plannedPerShard.Quo(plannedPerShard, big.NewInt(basisPoints))
	// Keep fractional per-shard rates until the final fleet-level floor. A
	// premature per-shard floor can materially understate a large fleet.
	usableFleet := new(big.Int).Mul(shards, big.NewInt(input.MeasuredPerShardTPS))
	usableFleet.Mul(usableFleet, big.NewInt(input.PlannedUtilizationBPS))
	usableFleet.Mul(usableFleet, big.NewInt(input.SurvivingCapacityBPS))
	usableFleet.Quo(usableFleet, big.NewInt(basisPoints*basisPoints))
	if !plannedPerShard.IsInt64() || !usableFleet.IsInt64() {
		return ShardEstimate{}, errors.New("estimated capacity exceeds int64")
	}
	return ShardEstimate{
		TotalShards: shards.Int64(), PlannedPerShardTPS: plannedPerShard.Int64(),
		UsableFleetTPS: usableFleet.Int64(),
	}, nil
}

func ceilQuotient(numerator, denominator *big.Int) *big.Int {
	adjusted := new(big.Int).Sub(new(big.Int).Set(denominator), big.NewInt(1))
	adjusted.Add(adjusted, numerator)
	return adjusted.Quo(adjusted, denominator)
}
