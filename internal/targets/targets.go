package targets

import "iscan/internal/model"

func BuiltinTargets() []model.Target {
	return []model.Target{
		{
			Name:     "example-control",
			Domain:   "example.com",
			Scheme:   "https",
			Ports:    []int{443},
			Control:  true,
			HTTPPath: "/",
			QUICPort: 443,
		},
		{
			Name:     "cloudflare-control",
			Domain:   "cloudflare.com",
			Scheme:   "https",
			Ports:    []int{443},
			Control:  true,
			HTTPPath: "/",
			QUICPort: 443,
		},
		{
			Name:       "google-diagnostic",
			Domain:     "www.google.com",
			Scheme:     "https",
			Ports:      []int{443},
			HTTPPath:   "/",
			CompareSNI: []string{"example.com"},
			QUICPort:   443,
		},
	}
}

func BuiltinResolvers() []model.Resolver {
	return []model.Resolver{
		{Name: "system", System: true},
		{Name: "cloudflare", Server: "1.1.1.1:53"},
		{Name: "google", Server: "8.8.8.8:53"},
	}
}
