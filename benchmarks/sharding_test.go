package benchmarks

import "testing"

func TestEstimateLedgerShardsUsesMeasuredCapacityAndConservativeRounding(t *testing.T) {
	estimate, err := EstimateLedgerShards(ShardAssumptions{
		TargetTPS: 100_000, MeasuredPerShardTPS: 2_500,
		PlannedUtilizationBPS: 6_500, SurvivingCapacityBPS: 7_500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if estimate.TotalShards != 83 {
		t.Fatalf("expected conservative ceil to 83 shards, got %+v", estimate)
	}
	if estimate.UsableFleetTPS < 100_000 {
		t.Fatalf("estimated surviving capacity does not satisfy target: %+v", estimate)
	}
}

func TestEstimateLedgerShardsRejectsUnmeasuredOrImpossibleInputs(t *testing.T) {
	invalid := []ShardAssumptions{
		{},
		{TargetTPS: 1, MeasuredPerShardTPS: 0, PlannedUtilizationBPS: 1, SurvivingCapacityBPS: 1},
		{TargetTPS: 1, MeasuredPerShardTPS: 1, PlannedUtilizationBPS: 10_001, SurvivingCapacityBPS: 10_000},
	}
	for _, input := range invalid {
		if _, err := EstimateLedgerShards(input); err == nil {
			t.Fatalf("expected invalid assumptions to fail: %+v", input)
		}
	}
}

func TestEstimateLedgerShardsDefersFractionalRoundingToFleetLevel(t *testing.T) {
	estimate, err := EstimateLedgerShards(ShardAssumptions{
		TargetTPS: 1, MeasuredPerShardTPS: 1,
		PlannedUtilizationBPS: 5_000, SurvivingCapacityBPS: 10_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if estimate.TotalShards != 2 || estimate.UsableFleetTPS != 1 {
		t.Fatalf("fractional per-shard capacity was rounded too early: %+v", estimate)
	}
}
