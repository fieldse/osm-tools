package cmd

import "os"

// resolveBaseURL returns the API base URL, honoring the OSM_BASE_URL test/staging
// seam when set.
func resolveBaseURL() string {
	if v := os.Getenv("OSM_BASE_URL"); v != "" {
		return v
	}
	return defaultBaseURL
}
