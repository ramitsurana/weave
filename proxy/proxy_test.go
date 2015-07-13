package proxy

import (
	"testing"
)

func TestParseHostname(t *testing.T) {
	hostnameExpr := `/aws-[0-9]+-(.*)/my-app-$1/`

	patternRegexp, replacementStr, err := parseHostname(hostnameExpr)
	if err != nil {
		t.Error("Unexpected error", err)
	}
	if replacementStr != "my-app-$1" {
		t.Error("Unexpected replacement string", replacementStr)
	}

	hostname := patternRegexp.ReplaceAllString("aws-17651276812-name", replacementStr)
	if hostname != "my-app-name" {
		t.Error("Unexpected replacement hostname", hostname)
	}
}

func TestParseWrongHostname(t *testing.T) {
	wrongHostnameExprs := []string{
		`/`,
		`//`,
		`/ /`,
		`/ / / /`,
		`/aws-[0-9]+-(.*)/my-app-$1/ /`,
		`/ /aws-[0-9]+-(.*)/my-app-$1/`,
		`/ /aws-[0-9]+-(.*)/my-app-$1/ /`,
	}

	for _, hostnameExpr := range wrongHostnameExprs {
		_, _, err := parseHostname(hostnameExpr)
		if err == nil {
			t.Error("Should not succesully parse wrong hostname expression", hostnameExpr)
		}
	}
}

func TestEscapedHostname(t *testing.T) {
	hostnameExpr := `/aws\/[0-9]+\/(.*)/my\/app\/$1/`

	patternRegexp, replacementStr, err := parseHostname(hostnameExpr)
	if err != nil {
		t.Error("Unexpected error", err)
	}
	if replacementStr != "my/app/$1" {
		t.Error("Unexpected replacement string", replacementStr)
	}

	hostname := patternRegexp.ReplaceAllString("aws/17651276812/name", replacementStr)
	if hostname != "my/app/name" {
		t.Error("Unexpected replacement hostname", hostname)
	}

}
