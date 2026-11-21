package config

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	gv "github.com/hashicorp/go-version"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/version"
)

var (
	//go:embed gitleaks.toml
	DefaultConfig string

	// extendDepth is retained for source compatibility. Translation now
	// carries the extension depth explicitly so concurrent config loads cannot
	// share parser state.
	extendDepth int
)

const maxExtendDepth = 2

// ViperConfig is the config struct used by the Viper config package
// to parse the config file. This struct does not include regular expressions.
// It is used as an intermediary to convert the Viper config to the Config struct.
type ViperConfig struct {
	Title       string
	Description string
	Extend      Extend
	Rules       []struct {
		ID          string
		Description string
		Path        string
		Regex       string
		SecretGroup int
		Entropy     float64
		Keywords    []string
		Tags        []string

		// Deprecated: this is a shim for backwards-compatibility.
		// TODO: Remove this in 9.x.
		AllowList *viperRuleAllowlist

		Allowlists []*viperRuleAllowlist
		Required   []*viperRequired
		SkipReport bool
	}
	// Deprecated: this is a shim for backwards-compatibility.
	// TODO: Remove this in 9.x.
	AllowList *viperGlobalAllowlist

	Allowlists []*viperGlobalAllowlist

	MinVersion string

	configPath string
	pathSet    bool
}

type viperRequired struct {
	ID            string
	WithinLines   *int `mapstructure:"withinLines"`
	WithinColumns *int `mapstructure:"withinColumns"`
}

type viperRuleAllowlist struct {
	Description string
	Condition   string
	Commits     []string
	Paths       []string
	RegexTarget string
	Regexes     []string
	StopWords   []string
}

type viperGlobalAllowlist struct {
	TargetRules        []string
	viperRuleAllowlist `mapstructure:",squash"`
}

// Config is a configuration struct that contains rules and an allowlist if present.
type Config struct {
	Title       string
	Extend      Extend
	Path        string
	// Version is a deterministic fingerprint of the complete, effective
	// configuration. It is computed after extension and validation, so every
	// rule and allowlist used by a scan is represented by the same version.
	Version     string
	Description string
	Rules       map[string]Rule
	Keywords    map[string]struct{}
	// used to keep sarif results consistent
	OrderedRules []string
	Allowlists   []*Allowlist
	MinVersion   string
}

// Extend is a struct that allows users to define how they want their
// configuration extended by other configuration files.
type Extend struct {
	Path          string
	URL           string
	UseDefault    bool
	DisabledRules []string
}

func (vc *ViperConfig) Translate() (Config, error) {
	return vc.translate(0)
}

// SetConfigPath sets the source path used to resolve relative extends and to
// identify the config in reports. It also prevents Translate from falling back
// to Viper's process-global ConfigFileUsed value.
func (vc *ViperConfig) SetConfigPath(path string) {
	vc.configPath = path
	vc.pathSet = true
}

func (vc *ViperConfig) translate(depth int) (Config, error) {
	if depth == 0 && !vc.pathSet {
		vc.configPath = viper.ConfigFileUsed()
		vc.pathSet = true
	}

	var (
		keywords       = make(map[string]struct{})
		orderedRules   []string
		rulesMap       = make(map[string]Rule)
		ruleAllowlists = make(map[string][]*Allowlist)
	)

	// Validate individual rules.
	for _, vr := range vc.Rules {
		var (
			pathPat  *regexp.Regexp
			regexPat *regexp.Regexp
		)
		if vr.Path != "" {
			pathPat = regexp.MustCompile(vr.Path)
		}
		if vr.Regex != "" {
			regexPat = regexp.MustCompile(vr.Regex)
		}
		if vr.Keywords == nil {
			vr.Keywords = []string{}
		} else {
			for i, k := range vr.Keywords {
				keyword := strings.ToLower(k)
				keywords[keyword] = struct{}{}
				vr.Keywords[i] = keyword
			}
		}
		if vr.Tags == nil {
			vr.Tags = []string{}
		}
		cr := Rule{
			RuleID:      vr.ID,
			Description: vr.Description,
			Regex:       regexPat,
			SecretGroup: vr.SecretGroup,
			Entropy:     vr.Entropy,
			Path:        pathPat,
			Keywords:    vr.Keywords,
			Tags:        vr.Tags,
			SkipReport:  vr.SkipReport,
		}

		// Parse the rule allowlists, including the older format for backwards compatibility.
		if vr.AllowList != nil {
			// TODO: Remove this in v9.
			if len(vr.Allowlists) > 0 {
				return Config{}, fmt.Errorf("%s: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]", cr.RuleID)
			}
			vr.Allowlists = append(vr.Allowlists, vr.AllowList)
		}
		for _, a := range vr.Allowlists {
			allowlist, err := vc.parseAllowlist(a)
			if err != nil {
				return Config{}, fmt.Errorf("%s: [[rules.allowlists]] %w", cr.RuleID, err)
			}
			cr.Allowlists = append(cr.Allowlists, allowlist)
		}

		for _, r := range vr.Required {
			if r.ID == "" {
				return Config{}, fmt.Errorf("%s: [[rules.required]] rule ID is empty", cr.RuleID)
			}
			requiredRule := Required{
				RuleID:        r.ID,
				WithinLines:   r.WithinLines,
				WithinColumns: r.WithinColumns,
				// Distance: r.Distance,
			}
			cr.RequiredRules = append(cr.RequiredRules, &requiredRule)
		}

		orderedRules = append(orderedRules, cr.RuleID)
		rulesMap[cr.RuleID] = cr
	}

	// after all the rules have been processed, let's ensure the required rules
	// actually exist.
	for _, r := range rulesMap {
		for _, rr := range r.RequiredRules {
			if _, ok := rulesMap[rr.RuleID]; !ok {
				return Config{}, fmt.Errorf("%s: [[rules.required]] rule ID '%s' does not exist", r.RuleID, rr.RuleID)
			}
		}
	}

	// Assemble the config.
	c := Config{
		Title:        vc.Title,
		Description:  vc.Description,
		Extend:       vc.Extend,
		Rules:        rulesMap,
		Keywords:     keywords,
		OrderedRules: orderedRules,
		MinVersion:   vc.MinVersion,
	}

	c.Path = vc.configPath

	if err := validateMinVersion(c.MinVersion, c.Path); err != nil {
		return Config{}, err
	}

	// Parse the config allowlists, including the older format for backwards compatibility.
	if vc.AllowList != nil {
		// TODO: Remove this in v9.
		if len(vc.Allowlists) > 0 {
			return Config{}, errors.New("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]")
		}
		vc.Allowlists = append(vc.Allowlists, vc.AllowList)
	}
	for _, a := range vc.Allowlists {
		allowlist, err := vc.parseAllowlist(&a.viperRuleAllowlist)
		if err != nil {
			return Config{}, fmt.Errorf("[[allowlists]] %w", err)
		}
		// Allowlists with |targetRules| aren't added to the global list.
		if len(a.TargetRules) > 0 {
			for _, ruleID := range a.TargetRules {
				// It's not possible to validate |ruleID| until after extend.
				ruleAllowlists[ruleID] = append(ruleAllowlists[ruleID], allowlist)
			}
		} else {
			c.Allowlists = append(c.Allowlists, allowlist)
		}
	}

	currentExtendDepth := depth
	if maxExtendDepth != currentExtendDepth {
		// disallow both usedefault and path from being set
		if c.Extend.Path != "" && c.Extend.UseDefault {
			return Config{}, errors.New("unable to load config due to extend.path and extend.useDefault being set")
		}
		if c.Extend.UseDefault {
			if err := c.extendDefault(depth + 1); err != nil {
				return Config{}, err
			}
		} else if c.Extend.Path != "" {
			if err := c.extendPath(depth + 1); err != nil {
				return Config{}, err
			}
		}
	}

	// Validate the rules after everything has been assembled (including extended configs).
	if currentExtendDepth == 0 {
		for _, rule := range c.Rules {
			if err := rule.Validate(); err != nil {
				return Config{}, err
			}
		}

		// Populate targeted configs.
		for ruleID, allowlists := range ruleAllowlists {
			rule, ok := c.Rules[ruleID]
			if !ok {
				return Config{}, fmt.Errorf("[[allowlists]] target rule ID '%s' does not exist", ruleID)
			}
			rule.Allowlists = append(rule.Allowlists, allowlists...)
			c.Rules[ruleID] = rule
		}
	}

	c.Version = c.computeVersion()
	return c, nil
}

func validateMinVersion(minVer string, configPath string) error {
	if minVer == "" {
		logging.Debug().Str("config path", configPath).
			Msg("no minVersion specified in config... consider adding minVersion to ensure compatibility.")
		return nil
	}

	if version.Version == version.DefaultMsg {
		logging.Debug().
			Str("required", minVer).
			Msg("dev build, skipping config version check.")
		return nil
	}

	minSemVer, err := gv.NewSemver(minVer)
	if err != nil {
		return fmt.Errorf("invalid minVersion '%s': %w", minVer, err)
	}

	currentSemVer, err := gv.NewSemver(version.Version)
	if err != nil {
		return fmt.Errorf("unable to parse current version: %w", err)
	}

	if currentSemVer.LessThan(minSemVer) {
		logging.Warn().
			Str("required", minVer).
			Str("current", version.Version).
			Str("config path", configPath).
			Msg("config requires a newer Gitleaks version...")
	}

	return nil
}

func (vc *ViperConfig) parseAllowlist(a *viperRuleAllowlist) (*Allowlist, error) {
	var matchCondition AllowlistMatchCondition
	switch strings.ToUpper(a.Condition) {
	case "AND", "&&":
		matchCondition = AllowlistMatchAnd
	case "", "OR", "||":
		matchCondition = AllowlistMatchOr
	default:
		return nil, fmt.Errorf("unknown allowlist |condition| '%s' (expected 'and', 'or')", a.Condition)
	}

	// Validate the target.
	regexTarget := a.RegexTarget
	if regexTarget != "" {
		switch regexTarget {
		case "secret":
			regexTarget = ""
		case "match", "line":
			// do nothing
		default:
			return nil, fmt.Errorf("unknown allowlist |regexTarget| '%s' (expected 'match', 'line')", regexTarget)
		}
	}
	var allowlistRegexes []*regexp.Regexp
	for _, a := range a.Regexes {
		allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
	}
	var allowlistPaths []*regexp.Regexp
	for _, a := range a.Paths {
		allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
	}

	allowlist := &Allowlist{
		Description:    a.Description,
		MatchCondition: matchCondition,
		Commits:        a.Commits,
		Paths:          allowlistPaths,
		RegexTarget:    regexTarget,
		Regexes:        allowlistRegexes,
		StopWords:      a.StopWords,
	}
	if err := allowlist.Validate(); err != nil {
		return nil, err
	}
	return allowlist, nil
}

func (c *Config) GetOrderedRules() []Rule {
	var orderedRules []Rule
	for _, id := range c.OrderedRules {
		if _, ok := c.Rules[id]; ok {
			orderedRules = append(orderedRules, c.Rules[id])
		}
	}
	return orderedRules
}

// LoadConfig loads and translates a configuration from a file.
//
// Unlike translating a ViperConfig that was populated through Viper's global
// instance, LoadConfig keeps all parser state local to the call.
func LoadConfig(path string) (Config, error) {
	loaded := viper.New()
	loaded.SetConfigType("toml")
	loaded.SetConfigFile(path)
	if err := loaded.ReadInConfig(); err != nil {
		return Config{}, err
	}

	var vc ViperConfig
	if err := loaded.Unmarshal(&vc); err != nil {
		return Config{}, err
	}
	vc.configPath = path
	vc.pathSet = true
	return vc.Translate()
}

// ParseConfig parses and translates a TOML configuration from memory.
func ParseConfig(content []byte) (Config, error) {
	loaded := viper.New()
	loaded.SetConfigType("toml")
	if err := loaded.ReadConfig(strings.NewReader(string(content))); err != nil {
		return Config{}, err
	}

	var vc ViperConfig
	if err := loaded.Unmarshal(&vc); err != nil {
		return Config{}, err
	}
	vc.pathSet = true
	return vc.Translate()
}

// Clone returns a deep copy of the configuration. Compiled regular expressions
// are immutable and are intentionally shared.
func (c Config) Clone() Config {
	clone := c
	clone.Extend.DisabledRules = append([]string(nil), c.Extend.DisabledRules...)
	clone.OrderedRules = append([]string(nil), c.OrderedRules...)
	clone.Allowlists = cloneAllowlists(c.Allowlists)

	clone.Rules = make(map[string]Rule, len(c.Rules))
	for id, rule := range c.Rules {
		clone.Rules[id] = cloneRule(rule)
	}

	clone.Keywords = make(map[string]struct{}, len(c.Keywords))
	for keyword := range c.Keywords {
		clone.Keywords[keyword] = struct{}{}
	}
	return clone
}

// Snapshot returns an immutable deep copy with a version computed from its
// complete effective contents. Scans should use a snapshot so later config
// edits cannot change the rules or allowlists midway through the scan.
func (c Config) Snapshot() Config {
	snapshot := c.Clone()
	snapshot.Version = snapshot.computeVersion()
	return snapshot
}

// RefreshVersion updates Version to match the current effective contents.
func (c *Config) RefreshVersion() {
	c.Version = c.computeVersion()
}

func cloneRule(rule Rule) Rule {
	clone := rule
	clone.Tags = append([]string(nil), rule.Tags...)
	clone.Keywords = append([]string(nil), rule.Keywords...)
	clone.Allowlists = cloneAllowlists(rule.Allowlists)
	if rule.RequiredRules != nil {
		clone.RequiredRules = make([]*Required, len(rule.RequiredRules))
		for i, required := range rule.RequiredRules {
			if required == nil {
				continue
			}
			requiredClone := *required
			clone.RequiredRules[i] = &requiredClone
		}
	}
	return clone
}

func cloneAllowlists(allowlists []*Allowlist) []*Allowlist {
	if allowlists == nil {
		return nil
	}
	clones := make([]*Allowlist, len(allowlists))
	for i, allowlist := range allowlists {
		if allowlist == nil {
			continue
		}
		clone := *allowlist
		clone.Commits = append([]string(nil), allowlist.Commits...)
		clone.Paths = append([]*regexp.Regexp(nil), allowlist.Paths...)
		clone.Regexes = append([]*regexp.Regexp(nil), allowlist.Regexes...)
		clone.StopWords = append([]string(nil), allowlist.StopWords...)
		clones[i] = &clone
	}
	return clones
}

func (c Config) computeVersion() string {
	hash := sha256.New()
	write := func(key, value string) {
		_, _ = fmt.Fprintf(hash, "%s=%d:%s\n", key, len(value), value)
	}

	write("title", c.Title)
	write("description", c.Description)
	write("minVersion", c.MinVersion)
	write("keywords", strings.Join(sortedStrings(mapKeys(c.Keywords)), "\x00"))

	ruleIDs := make([]string, 0, len(c.Rules))
	for id := range c.Rules {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	for _, id := range ruleIDs {
		write("rule:"+id, canonicalRule(c.Rules[id]))
	}

	allowlists := make([]string, 0, len(c.Allowlists))
	for _, allowlist := range c.Allowlists {
		allowlists = append(allowlists, canonicalAllowlist(allowlist))
	}
	sort.Strings(allowlists)
	for i, allowlist := range allowlists {
		write("allowlist:"+strconv.Itoa(i), allowlist)
	}

	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func canonicalRule(rule Rule) string {
	var b strings.Builder
	write := func(key, value string) {
		_, _ = fmt.Fprintf(&b, "%s=%d:%s\n", key, len(value), value)
	}

	write("id", rule.RuleID)
	write("description", rule.Description)
	write("regex", regexpString(rule.Regex))
	write("path", regexpString(rule.Path))
	write("entropy", strconv.FormatFloat(rule.Entropy, 'g', -1, 64))
	write("secretGroup", strconv.Itoa(rule.SecretGroup))
	write("skipReport", strconv.FormatBool(rule.SkipReport))
	write("tags", strings.Join(sortedStrings(rule.Tags), "\x00"))
	write("keywords", strings.Join(sortedStrings(rule.Keywords), "\x00"))

	allowlists := make([]string, 0, len(rule.Allowlists))
	for _, allowlist := range rule.Allowlists {
		allowlists = append(allowlists, canonicalAllowlist(allowlist))
	}
	sort.Strings(allowlists)
	for i, allowlist := range allowlists {
		write("allowlist:"+strconv.Itoa(i), allowlist)
	}

	required := make([]string, 0, len(rule.RequiredRules))
	for _, requiredRule := range rule.RequiredRules {
		if requiredRule == nil {
			continue
		}
		var rb strings.Builder
		_, _ = fmt.Fprintf(&rb, "id=%d:%s\n", len(requiredRule.RuleID), requiredRule.RuleID)
		_, _ = fmt.Fprintf(&rb, "withinLines=%s\n", optionalInt(requiredRule.WithinLines))
		_, _ = fmt.Fprintf(&rb, "withinColumns=%s\n", optionalInt(requiredRule.WithinColumns))
		required = append(required, rb.String())
	}
	sort.Strings(required)
	for i, requiredRule := range required {
		write("required:"+strconv.Itoa(i), requiredRule)
	}

	return b.String()
}

func canonicalAllowlist(allowlist *Allowlist) string {
	if allowlist == nil {
		return ""
	}

	var b strings.Builder
	write := func(key, value string) {
		_, _ = fmt.Fprintf(&b, "%s=%d:%s\n", key, len(value), value)
	}

	write("description", allowlist.Description)
	condition := "OR"
	if allowlist.MatchCondition == AllowlistMatchAnd {
		condition = "AND"
	}
	write("condition", condition)
	write("regexTarget", allowlist.RegexTarget)
	write("commits", strings.Join(sortedStrings(allowlist.Commits), "\x00"))
	write("stopwords", strings.Join(sortedStrings(allowlist.StopWords), "\x00"))

	paths := make([]string, 0, len(allowlist.Paths))
	for _, path := range allowlist.Paths {
		paths = append(paths, regexpString(path))
	}
	sort.Strings(paths)
	write("paths", strings.Join(paths, "\x00"))

	regexes := make([]string, 0, len(allowlist.Regexes))
	for _, regex := range allowlist.Regexes {
		regexes = append(regexes, regexpString(regex))
	}
	sort.Strings(regexes)
	write("regexes", strings.Join(regexes, "\x00"))

	return b.String()
}

func regexpString(regex *regexp.Regexp) string {
	if regex == nil {
		return ""
	}
	return regex.String()
}

func sortedStrings(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func optionalInt(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

func (c *Config) extendDefault(depth int) error {
	loaded := viper.New()
	loaded.SetConfigType("toml")
	if err := loaded.ReadConfig(strings.NewReader(DefaultConfig)); err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)
	}
	defaultViperConfig := ViperConfig{}
	if err := loaded.Unmarshal(&defaultViperConfig); err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)
	}
	// The default config is embedded, so it has no filesystem path.
	defaultViperConfig.pathSet = true
	cfg, err := defaultViperConfig.translate(depth)
	if err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)

	}
	logging.Debug().Msg("extending config with default config")
	c.extend(cfg)
	return nil
}

func (c *Config) extendPath(depth int) error {
	// Use a dedicated Viper instance so loading an extended config cannot
	// replace the global parser state used by another config translation.
	loaded := viper.New()
	loaded.SetConfigType("toml")
	loaded.SetConfigFile(c.Extend.Path)
	if err := loaded.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	extensionViperConfig := ViperConfig{}
	if err := loaded.Unmarshal(&extensionViperConfig); err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}

	extensionViperConfig.configPath = c.Extend.Path
	extensionViperConfig.pathSet = true
	logging.Debug().Msgf("extending config with %s", c.Extend.Path)
	cfg, err := extensionViperConfig.translate(depth)
	if err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	c.extend(cfg)
	return nil
}

func (c *Config) extendURL() {
	// TODO
}

func (c *Config) extend(extensionConfig Config) {
	// Get config name for helpful log messages.
	var configName string
	if c.Extend.Path != "" {
		configName = c.Extend.Path
	} else {
		configName = "default"
	}
	// Convert |Config.DisabledRules| into a map for ease of access.
	disabledRuleIDs := map[string]struct{}{}
	for _, id := range c.Extend.DisabledRules {
		if _, ok := extensionConfig.Rules[id]; !ok {
			logging.Warn().
				Str("rule-id", id).
				Str("config", configName).
				Msg("Disabled rule doesn't exist in extended config.")
		}
		disabledRuleIDs[id] = struct{}{}
	}

	for ruleID, baseRule := range extensionConfig.Rules {
		// Skip the rule.
		if _, ok := disabledRuleIDs[ruleID]; ok {
			logging.Debug().
				Str("rule-id", ruleID).
				Str("config", configName).
				Msg("Ignoring rule from extended config.")
			continue
		}

		currentRule, ok := c.Rules[ruleID]
		if !ok {
			// Rule doesn't exist, add it to the config.
			c.Rules[ruleID] = baseRule
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
			}
			c.OrderedRules = append(c.OrderedRules, ruleID)
		} else {
			// Rule exists, merge our changes into the base.
			if currentRule.Description != "" {
				baseRule.Description = currentRule.Description
			}
			if currentRule.Entropy != 0 {
				baseRule.Entropy = currentRule.Entropy
			}
			if currentRule.SecretGroup != 0 {
				baseRule.SecretGroup = currentRule.SecretGroup
			}
			if currentRule.Regex != nil {
				baseRule.Regex = currentRule.Regex
			}
			if currentRule.Path != nil {
				baseRule.Path = currentRule.Path
			}
			baseRule.Tags = append(baseRule.Tags, currentRule.Tags...)
			baseRule.Keywords = append(baseRule.Keywords, currentRule.Keywords...)
			baseRule.Allowlists = append(baseRule.Allowlists, currentRule.Allowlists...)
			// The keywords from the base rule and the extended rule must be merged into the global keywords list
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
			}
			c.Rules[ruleID] = baseRule
		}
	}

	// append allowlists, not attempting to merge
	c.Allowlists = append(c.Allowlists, extensionConfig.Allowlists...)

	// sort to keep extended rules in order
	sort.Strings(c.OrderedRules)
	return
}
