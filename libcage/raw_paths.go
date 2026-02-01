package libcage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ExpandCageInputs(inputs []string) ([]string, error) {
	var out []string
	for _, in := range inputs {
		st, err := os.Stat(in)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			ents, err := os.ReadDir(in)
			if err != nil {
				return nil, err
			}
			var names []string
			for _, ent := range ents {
				if ent.IsDir() {
					continue
				}
				if strings.HasSuffix(ent.Name(), ".cage") {
					names = append(names, ent.Name())
				}
			}
			sort.Strings(names)
			for _, n := range names {
				out = append(out, filepath.Join(in, n))
			}
			continue
		}
		if !strings.HasSuffix(in, ".cage") {
			return nil, fmt.Errorf("raw mode expects *.cage files or directories containing them, got %q", in)
		}
		out = append(out, in)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no *.cage inputs")
	}
	return out, nil
}
