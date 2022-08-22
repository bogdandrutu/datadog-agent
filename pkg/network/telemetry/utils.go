package telemetry

import (
	"sort"
	"strings"
)

func contains(want string, strings []string) bool {
	for _, candidate := range strings {
		if want == candidate {
			return true
		}
	}
	return false
}

// in-place partitioning of `all` into `tags` followed by `opts`
// Example: given {"_opt3", "tag:a", "_opt2", "tag:b", "_opt1", "tag:c"}
// The return value will be:
// {"tag:a", "tag:b", "tag:c"}
// {"_opt1", "_opt2", "_opt3"}
func separateTagsAndOptions(all []string) (tags, opts []string) {
	if len(all) == 0 {
		return
	}
	i := 0
	j := len(all) - 1
	for i <= j {
		if !strings.HasPrefix(all[i], optPrefix) {
			// all[i] is a tag
			i++
			continue
		}

		// all[i] is an opt
		if !strings.HasPrefix(all[j], optPrefix) {
			// all[j] is a tag
			all[i], all[j] = all[j], all[i]
			i++
			j--
			continue
		}

		// all[i] is opt
		// all[j] is opt
		j--
	}

	tags = all[:i]
	opts = all[i:]
	sort.Strings(tags)
	sort.Strings(opts)
	return
}

func insertNestedValueFor(name string, value int64, root map[string]interface{}) {
	parts := strings.Split(name, ".")
	if len(parts) == 1 {
		root[name] = value
		return
	}

	parent := root
	for i := 0; i < len(parts)-1; i++ {
		if v, ok := parent[parts[i]]; ok {
			child, ok := v.(map[string]interface{})

			if !ok {
				// shouldn't happen; bail out.
				return
			}

			parent = child
			continue
		}

		child := make(map[string]interface{})
		parent[parts[i]] = child
		parent = child
	}

	parent[parts[len(parts)-1]] = value
}
