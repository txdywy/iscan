package recommend_test

import (
	"testing"

	"iscan/internal/model"
	"iscan/internal/profile"
	"iscan/internal/recommend"
)

func TestRankProducesPrimaryCategoriesSorted(t *testing.T) {
	prof := profile.Profile{
		TCPHealth: profile.TCPHealth{
			SuccessRate: 0.9,
			Tier:        profile.QualityGood,
		},
		TLSHealth: profile.TLSHealth{
			SuccessRate:     0.8,
			HasSNIFiltering: false,
			Tier:            profile.QualityGood,
		},
		DNSHealth: profile.DNSHealth{
			Agreement: true,
			Tier:      profile.QualityExcellent,
		},
		PathHealth: profile.PathHealth{
			Reachable: true,
			Tier:      profile.QualityGood,
		},
		OverallStability: 0.75,
	}

	result := recommend.Rank(model.ScanReport{}, prof)

	if len(result.Rankings) != 4 {
		t.Fatalf("expected 4 rankings, got %d", len(result.Rankings))
	}
	// The last ranking is always the fallback (high-redundancy retry).
	primary := result.Rankings[:3]
	for i := 1; i < len(primary); i++ {
		if primary[i-1].Score < primary[i].Score {
			t.Fatalf("primary rankings not sorted descending: %s (%.2f) < %s (%.2f)",
				primary[i-1].Category, primary[i-1].Score,
				primary[i].Category, primary[i].Score)
		}
	}
	fallback := result.Rankings[3]
	if fallback.Category != "高重试鲁棒型 (high-redundancy retry)" {
		t.Fatalf("expected fallback as last ranking, got %s", fallback.Category)
	}
	for _, r := range result.Rankings {
		if r.Category == "" {
			t.Fatal("ranking category must not be empty")
		}
		if r.Score < 0 || r.Score > 1 {
			t.Fatalf("score %.2f out of bounds for %s", r.Score, r.Category)
		}
	}
}

func TestRankWithSNIFilteringPrefersConservative(t *testing.T) {
	prof := profile.Profile{
		TCPHealth: profile.TCPHealth{
			SuccessRate: 0.9,
			Tier:        profile.QualityGood,
		},
		TLSHealth: profile.TLSHealth{
			SuccessRate:     0.4,
			HasSNIFiltering: true,
			Tier:            profile.QualityFair,
		},
		DNSHealth: profile.DNSHealth{
			Agreement: true,
			Tier:      profile.QualityGood,
		},
		PathHealth: profile.PathHealth{
			Reachable: true,
			Tier:      profile.QualityFair,
			Jitter:    150000000, // 150ms — lowers UDP-friendly score enough for conservative to win
		},
		OverallStability: 0.5,
	}

	result := recommend.Rank(model.ScanReport{}, prof)
	top := result.Rankings[0]

	if top.Category != "保守TCP/TLS型 (conservative TCP/TLS)" {
		t.Fatalf("expected conservative to rank first when SNI filtering detected, got %s", top.Category)
	}
	if top.Score <= 0 {
		t.Fatalf("expected non-zero top score: %#v", top)
	}
}
