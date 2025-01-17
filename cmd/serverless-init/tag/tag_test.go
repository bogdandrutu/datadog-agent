// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package tag

import (
	"os"
	"sort"
	"testing"

	"gotest.tools/assert"
)

func TestGetBaseTagsArrayNoEnvNoMetadata(t *testing.T) {
	assert.Equal(t, 1, len(GetBaseTagsArrayWithMetadataTags(make(map[string]string, 0))))
}

func TestGetBaseTagsArrayWithMetadataTagsNoMetadata(t *testing.T) {
	os.Setenv("K_SERVICE", "myService")
	defer os.Unsetenv("K_SERVICE")
	os.Setenv("K_REVISION", "FDGF34")
	defer os.Unsetenv("K_REVISION")
	os.Setenv("DD_ENV", "myEnv")
	defer os.Unsetenv("DD_ENV")
	os.Setenv("DD_SERVICE", "superService")
	defer os.Unsetenv("DD_SERVICE")
	os.Setenv("DD_VERSION", "123.4")
	defer os.Unsetenv("DD_VERSION")
	tags := GetBaseTagsArrayWithMetadataTags(make(map[string]string, 0))
	sort.Strings(tags)
	assert.Equal(t, 6, len(tags))
	assert.Equal(t, "env:myenv", tags[0])
	assert.Equal(t, "origin:cloudrun", tags[1])
	assert.Equal(t, "revision_name:fdgf34", tags[2])
	assert.Equal(t, "service:superservice", tags[3])
	assert.Equal(t, "service_name:myservice", tags[4])
	assert.Equal(t, "version:123.4", tags[5])
}

func TestGetTagFound(t *testing.T) {
	os.Setenv("TOTO", "coucou")
	defer os.Unsetenv("TOTO")
	value, found := getTag("TOTO")
	assert.Equal(t, true, found)
	assert.Equal(t, "coucou", value)
}

func TestGetTagNotFound(t *testing.T) {
	value, found := getTag("XXX")
	assert.Equal(t, false, found)
	assert.Equal(t, "", value)
}

func TestGetBaseTagsMapNoEnvNoMetadata(t *testing.T) {
	assert.Equal(t, 1, len(GetBaseTagsMapWithMetadata(make(map[string]string, 0))))
}

func TestGetBaseTagsMapNoMetadata(t *testing.T) {
	os.Setenv("K_SERVICE", "myService")
	defer os.Unsetenv("K_SERVICE")
	os.Setenv("K_REVISION", "FDGF34")
	defer os.Unsetenv("K_REVISION")
	os.Setenv("DD_ENV", "myEnv")
	defer os.Unsetenv("DD_ENV")
	os.Setenv("DD_SERVICE", "superService")
	defer os.Unsetenv("DD_SERVICE")
	os.Setenv("DD_VERSION", "123.4")
	defer os.Unsetenv("DD_VERSION")
	tags := GetBaseTagsMapWithMetadata(make(map[string]string, 0))
	assert.Equal(t, 6, len(tags))
	assert.Equal(t, "myenv", tags["env"])
	assert.Equal(t, "fdgf34", tags["revision_name"])
	assert.Equal(t, "superservice", tags["service"])
	assert.Equal(t, "myservice", tags["service_name"])
	assert.Equal(t, "123.4", tags["version"])
	assert.Equal(t, "cloudrun", tags["origin"])
}

func TestGetBaseTagsMapWithMetadata(t *testing.T) {
	os.Setenv("K_SERVICE", "myService")
	defer os.Unsetenv("K_SERVICE")
	tags := GetBaseTagsMapWithMetadata(map[string]string{
		"location":      "mysuperlocation",
		"othermetadata": "mysuperothermetadatavalue",
	})
	assert.Equal(t, 4, len(tags))
	assert.Equal(t, "mysuperlocation", tags["location"])
	assert.Equal(t, "mysuperothermetadatavalue", tags["othermetadata"])
	assert.Equal(t, "myservice", tags["service_name"])
	assert.Equal(t, "cloudrun", tags["origin"])
}

func TestGetBaseTagsArrayWithMetadataTags(t *testing.T) {
	os.Setenv("K_REVISION", "FDGF34")
	defer os.Unsetenv("K_REVISION")
	tags := GetBaseTagsArrayWithMetadataTags(map[string]string{
		"location":      "mysuperlocation",
		"othermetadata": "mysuperothermetadatavalue",
	})
	sort.Strings(tags)
	assert.Equal(t, 4, len(tags))
	assert.Equal(t, "location:mysuperlocation", tags[0])
	assert.Equal(t, "origin:cloudrun", tags[1])
	assert.Equal(t, "othermetadata:mysuperothermetadatavalue", tags[2])
	assert.Equal(t, "revision_name:fdgf34", tags[3])

}
