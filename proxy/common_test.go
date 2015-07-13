package proxy

import (
	"reflect"
	"regexp"
	"testing"
)

func TestFindStringNamedSubmatch(t *testing.T) {
	re := regexp.MustCompile(`^(prefix) (?P<fooGroup>foo)(?P<barGroup>bar) (suffix)$`)
	expectedResult := map[string]string{
		"fooGroup": "foo",
		"barGroup": "bar",
	}
	namedSubmatches := findStringNamedSubmatch(re, "prefix foobar suffix")
	if !reflect.DeepEqual(namedSubmatches, expectedResult) {
		t.Error("Unexpected result", namedSubmatches)
	}
}
