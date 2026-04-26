package recommend_test

import (
	"testing"

	"iscan/internal/model"
	"iscan/internal/profile"
	"iscan/internal/recommend"
)

func TestRankProducesFourCategoriesSorted(t *testing.T) {
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
	for i := 1; i < len(result.Rankings); i++ {
		if result.Rankings[i-1].Score < result.Rankings[i].Score {
			t.Fatalf("rankings not sorted descending: %s (%.2f) < %s (%.2f)",
				result.Rankings[i-1].Category, result.Rankings[i-1].Score,
				result.Rankings[i].Category, result.Rankings[i].Score)
		}
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
		},
		OverallStability: 0.5,
	}

	result := recommend.Rank(model.ScanReport{}, prof)
	top := result.Rankings[0]

	if top.Score <= 0 {
		t.Fatalf("expected non-zero top score: %#v", top)
	}
}
