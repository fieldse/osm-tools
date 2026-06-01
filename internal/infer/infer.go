// Package infer classifies a resource identifier into an OSM check type.
package infer

import (
	"net"
	"strings"
)

// Check types.
const (
	TypePackage = "package"
	TypeDomain  = "domain"
	TypeIP      = "ip"
	TypeDocker  = "docker"
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

// Type determines the check type from the input, applied in order:
//
//	IP address           → ip
//	contains ":" or a
//	  known registry pfx → docker
//	contains "."         → domain
//	otherwise            → package (the default)
func Type(input string) string {
	if net.ParseIP(input) != nil {
		return TypeIP
	}
	if strings.Contains(input, ":") || hasRegistryPrefix(input) {
		return TypeDocker
	}
	if strings.Contains(input, ".") {
		return TypeDomain
	}
	return TypePackage
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
