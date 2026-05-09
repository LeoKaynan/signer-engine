package utils

import (
	"strings"
	"testing"
)

func RequireError(t testing.TB, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error")
	}
}

func RequireErrorContains(t testing.TB, err error, substr string) {
	t.Helper()

	RequireError(t, err)
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("unexpected error: got=%q want substring=%q", err.Error(), substr)
	}
}
