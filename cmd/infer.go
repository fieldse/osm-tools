package cmd

import (
	"net"
	"strings"
)

// supported check types.
const (
	typePackage = "package"
	typeDomain  = "domain"
	typeIP      = "ip"
	typeDocker  = "docker"
)

// dockerRegistryPrefixes are well-known registry hosts that mark an input as a
// container image even when no tag is present. (Open question in PLAN: confirm
// the authoritative list against OSM docs.)
var dockerRegistryPrefixes = []string{
	"docker.io/",
	"ghcr.io/",
	"quay.io/",
	"gcr.io/",
	"registry.k8s.io/",
	"public.ecr.aws/",
	"mcr.microsoft.com/",
}

// inferType determines the check type from the input, applied in order:
//
//	IP address           → ip
//	contains ":" or a
//	  known registry pfx → docker
//	contains "."         → domain
//	otherwise            → package (the default)
//
// hasEcosystem reports whether --ecosystem was provided; it does not change
// inference but is used by validation downstream.
func inferType(input string) string {
	if net.ParseIP(input) != nil {
		return typeIP
	}
	if strings.Contains(input, ":") || hasRegistryPrefix(input) {
		return typeDocker
	}
	if strings.Contains(input, ".") {
		return typeDomain
	}
	return typePackage
}

func hasRegistryPrefix(input string) bool {
	for _, p := range dockerRegistryPrefixes {
		if strings.HasPrefix(input, p) {
			return true
		}
	}
	return false
}

// isSupportedType reports whether t is a valid --type value.
func isSupportedType(t string) bool {
	switch t {
	case typePackage, typeDomain, typeIP, typeDocker:
		return true
	default:
		return false
	}
}
