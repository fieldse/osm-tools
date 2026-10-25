// Package infer classifies a resource identifier into an OSM check type.
package infer

import (
	"net"
	"regexp"
	"strings"
)

// Check types.
const (
	TypePackage = "package"
	TypeDomain  = "domain"
	TypeIP      = "ip"
	TypeDocker  = "docker"
)

// Asset types OSM tracks but check does not support.
const (
	TypeRepository = "repository"
	TypeURL        = "url"
	TypeWallet     = "wallet"
)

// dockerRegistryPrefixes are well-known registry hosts that mark an input as a
// container image even when no tag is present.
var dockerRegistryPrefixes = []string{
	"docker.io/",
	"ghcr.io/",
	"quay.io/",
	"gcr.io/",
	"registry.k8s.io/",
	"public.ecr.aws/",
	"mcr.microsoft.com/",
}

var (
	// evmWallet matches an Ethereum-style address: 0x and 40 hex digits.
	evmWallet = regexp.MustCompile(`^0[xX][0-9a-fA-F]{40}$`)

	// bech32Wallet matches a native SegWit Bitcoin address in one case.
	bech32Wallet = regexp.MustCompile(`^(bc1[02-9ac-hj-np-z]{11,71}|BC1[02-9AC-HJ-NP-Z]{11,71})$`)

	// urlScheme matches any "<scheme>://" prefix (https, ssh, git+https, ftp, …).
	urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

	// scpRepo matches git's scp-like form, user@host.tld:path. The dotted host
	// keeps image digests such as name@sha256:… out.
	scpRepo = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+:`)
)

// Type determines the check type from the input, applied in order:
//
//	<scheme>://            → url
//	user@host.tld:path     → repository
//	wallet address         → wallet
//	IP address             → ip
//	contains ":" or a
//	  known registry pfx   → docker
//	host.tld/path          → repository (a domain has no "/")
//	contains "."           → domain
//	otherwise              → package (the default)
func Type(input string) string {
	if urlScheme.MatchString(input) {
		return TypeURL
	}
	if scpRepo.MatchString(input) {
		return TypeRepository
	}
	if isWallet(input) {
		return TypeWallet
	}
	if net.ParseIP(input) != nil {
		return TypeIP
	}
	if strings.Contains(input, ":") || hasRegistryPrefix(input) {
		return TypeDocker
	}
	if isHostPath(input) {
		return TypeRepository
	}
	if strings.Contains(input, ".") {
		return TypeDomain
	}
	return TypePackage
}

// isHostPath reports whether input is a dotted host followed by a path, such
// as github.com/owner/repo.
func isHostPath(input string) bool {
	host, path, ok := strings.Cut(input, "/")
	return ok && path != "" && strings.Contains(host, ".")
}

func isWallet(input string) bool {
	return evmWallet.MatchString(input) || bech32Wallet.MatchString(input)
}

func hasRegistryPrefix(input string) bool {
	for _, p := range dockerRegistryPrefixes {
		if strings.HasPrefix(input, p) {
			return true
		}
	}
	return false
}

// IsSupported reports whether t is a valid check type.
func IsSupported(t string) bool {
	switch t {
	case TypePackage, TypeDomain, TypeIP, TypeDocker:
		return true
	default:
		return false
	}
}

// IsUnsupportedAsset reports whether t is an asset type that check rejects.
func IsUnsupportedAsset(t string) bool {
	switch t {
	case TypeRepository, TypeURL, TypeWallet:
		return true
	default:
		return false
	}
}

// NormalizeDomain lowercases a domain and strips one trailing root dot.
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}
