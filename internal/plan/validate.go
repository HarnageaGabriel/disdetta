package plan

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

func validShapeName(shape string) bool {
	switch shape {
	case "quantity", "dns-label", "pg-identifier", "resources", "int":
		return true
	}
	return strings.HasPrefix(shape, "enum:") && len(strings.TrimPrefix(shape, "enum:")) > 0
}

func acceptsValue(shape string, value any) bool {
	if hasDeniedKey(value) || hasUnsafeText(value) {
		return false
	}
	switch shape {
	case "quantity":
		s, ok := value.(string)
		if !ok || s == "" {
			return false
		}
		_, err := resource.ParseQuantity(s)
		return err == nil
	case "dns-label":
		s, ok := value.(string)
		return ok && len(validation.IsDNS1123Label(s)) == 0
	case "pg-identifier":
		s, ok := value.(string)
		if !ok || len(s) == 0 || len(s) > 63 {
			return false
		}
		for i, r := range s {
			if i == 0 {
				if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
					return false
				}
				continue
			}
			if r != '_' && r != '$' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
				return false
			}
		}
		return true
	case "resources":
		return acceptsResources(value)
	case "int":
		_, ok := integer(value)
		return ok
	}
	if strings.HasPrefix(shape, "enum:") {
		s, ok := value.(string)
		if !ok {
			return false
		}
		for _, allowed := range strings.Split(strings.TrimPrefix(shape, "enum:"), "|") {
			if s == allowed {
				return true
			}
		}
	}
	return false
}

func acceptsResources(value any) bool {
	resources, ok := value.(map[string]any)
	if !ok || len(resources) == 0 {
		return false
	}
	for class, raw := range resources {
		if class != "limits" && class != "requests" || deniedKey(class) {
			return false
		}
		values, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		for name, rawQuantity := range values {
			validName := name == "cpu" || name == "memory" || name == "ephemeral-storage"
			if strings.HasPrefix(name, "hugepages-") {
				_, err := resource.ParseQuantity(strings.TrimPrefix(name, "hugepages-"))
				validName = err == nil
			}
			if deniedKey(name) || !validName {
				return false
			}
			quantity, ok := rawQuantity.(string)
			if !ok {
				return false
			}
			if _, err := resource.ParseQuantity(quantity); err != nil {
				return false
			}
		}
	}
	return true
}

func hasDeniedKey(value any) bool {
	switch x := value.(type) {
	case map[string]any:
		for key, child := range x {
			if deniedKey(key) || hasDeniedKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if hasDeniedKey(child) {
				return true
			}
		}
	}
	return false
}

func deniedKey(key string) bool {
	key = strings.ToLower(key)
	for _, word := range []string{"password", "passwd", "secret", "token", "key", "credential", "passphrase"} {
		if strings.Contains(key, word) {
			return true
		}
	}
	return false
}

func hasUnsafeText(value any) bool {
	switch x := value.(type) {
	case string:
		for len(x) > 0 {
			r, size := utf8.DecodeRuneInString(x)
			if r == utf8.RuneError && size == 1 || !unicode.IsPrint(r) || unicode.In(r, unicode.Cf) {
				return true
			}
			x = x[size:]
		}
	case map[string]any:
		for key, child := range x {
			if hasUnsafeText(key) || hasUnsafeText(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if hasUnsafeText(child) {
				return true
			}
		}
	case []string:
		for _, child := range x {
			if hasUnsafeText(child) {
				return true
			}
		}
	}
	return false
}
