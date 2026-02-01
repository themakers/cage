package libcage

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type SecretV1 struct {
	Kind   string     `yaml:"kind"`
	Secret SecretBody `yaml:"secret"`
}

type SecretBody struct {
	Name            string   `yaml:"name"`
	PlaintextSHA256 string   `yaml:"plaintext_sha256,omitempty"`
	Payload         string   `yaml:"payload"`
	Recipients      []string `yaml:"recipients"`
}

type EnvironmentV1 struct {
	Kind        string          `yaml:"kind"`
	Environment EnvironmentBody `yaml:"environment"`
}

type EnvironmentBody struct {
	Name    string     `yaml:"name"`
	Secrets []SecretV1 `yaml:"secrets"`
}

var wsRe = regexp.MustCompile(`\s+`)

func DecodePayload(payload string) ([]byte, error) {
	clean := wsRe.ReplaceAllString(payload, "")
	b, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func EncodePayload(ciphertext []byte) string {
	s := base64.StdEncoding.EncodeToString(ciphertext)
	return Wrap(s, 86)
}

func Wrap(s string, width int) string {
	if width <= 0 {
		return s
	}
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteByte('\n')
		s = s[width:]
	}
	b.WriteString(s)
	b.WriteByte('\n')
	return b.String()
}

func NormalizeRecipients(recs []string) []string {
	set := map[string]struct{}{}
	var out []string
	for _, r := range recs {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := set[r]; ok {
			continue
		}
		set[r] = struct{}{}
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// ReadKind returns the top-level kind from a cage file.
func ReadKind(b []byte) (string, error) {
	var hdr struct {
		Kind string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(b, &hdr); err != nil {
		return "", err
	}
	return hdr.Kind, nil
}

func ParseSecretV1(b []byte) (*SecretV1, error) {
	var s SecretV1
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Kind != "secret/v1" {
		return nil, fmt.Errorf("unexpected kind %q", s.Kind)
	}
	s.Secret.Recipients = NormalizeRecipients(s.Secret.Recipients)
	// keep payload as-is (can include newlines); DecodePayload normalizes.
	return &s, nil
}

func ParseEnvironmentV1(b []byte) (*EnvironmentV1, error) {
	var e EnvironmentV1
	if err := yaml.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	if e.Kind != "environment/v1" {
		return nil, fmt.Errorf("unexpected kind %q", e.Kind)
	}
	// normalize embedded secret recipients for stable comparisons.
	for i := range e.Environment.Secrets {
		e.Environment.Secrets[i].Secret.Recipients = NormalizeRecipients(e.Environment.Secrets[i].Secret.Recipients)
	}
	return &e, nil
}

func MarshalSecretStable(s *SecretV1) ([]byte, error) {
	s2 := *s
	s2.Kind = "secret/v1"
	s2.Secret.Recipients = NormalizeRecipients(s2.Secret.Recipients)

	root := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{mapNode(
		scalar("kind"), scalar("secret/v1"),
		scalar("secret"), mapNode(
			scalar("name"), scalar(s2.Secret.Name),
			scalar("plaintext_sha256"), scalar(s2.Secret.PlaintextSHA256),
			scalar("payload"), literal(s2.Secret.Payload),
			scalar("recipients"), seqStrings(s2.Secret.Recipients),
		),
	)}}
	return encodeYAML(root)
}

func MarshalEnvironmentStable(e *EnvironmentV1) ([]byte, error) {
	e2 := *e
	e2.Kind = "environment/v1"

	// secrets are expected to already be in correct order; normalize recipients.
	secretsNode := &yaml.Node{Kind: yaml.SequenceNode}
	for _, s := range e2.Environment.Secrets {
		s.Kind = "secret/v1"
		s.Secret.Recipients = NormalizeRecipients(s.Secret.Recipients)

		item := mapNode(
			scalar("kind"), scalar("secret/v1"),
			scalar("secret"), mapNode(
				scalar("name"), scalar(s.Secret.Name),
				scalar("plaintext_sha256"), scalar(s.Secret.PlaintextSHA256),
				scalar("payload"), literal(s.Secret.Payload),
				scalar("recipients"), seqStrings(s.Secret.Recipients),
			),
		)
		secretsNode.Content = append(secretsNode.Content, item)
	}

	root := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{mapNode(
		scalar("kind"), scalar("environment/v1"),
		scalar("environment"), mapNode(
			scalar("name"), scalar(e2.Environment.Name),
			scalar("secrets"), secretsNode,
		),
	)}}
	return encodeYAML(root)
}

func encodeYAML(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mapNode(kv ...*yaml.Node) *yaml.Node {
	if len(kv)%2 != 0 {
		panic("mapNode: odd kv")
	}
	m := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, kv...)
	return m
}

func scalar(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func literal(v string) *yaml.Node {
	n := scalar(v)
	n.Style = yaml.LiteralStyle
	return n
}

func seqStrings(vs []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode}
	for _, v := range vs {
		n.Content = append(n.Content, scalar(v))
	}
	return n
}
