package main

import "testing"

func TestProductionConfigurationRejectsInsecureDatabase(t *testing.T) {
	for key, value := range map[string]string{
		"DATABASE_URL": "postgresql://worker@db:26257/payments?sslmode=disable",
		"ENVIRONMENT":  "production", "REGION_ID": "pay-a", "ID_ISSUER": "reconciliation-a",
	} {
		t.Setenv(key, value)
	}
	_, err := loadConfig()
	if err == nil {
		t.Fatal("production worker accepted an insecure database URL")
	}
}
