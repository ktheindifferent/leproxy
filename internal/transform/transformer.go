// Package transform provides request and response transformation capabilities
package transform

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/artyom/leproxy/internal/logger"
)

// Transformer handles request and response transformations
type Transformer struct {
	rules           []Rule
	enabledFeatures map[string]bool
}

// Rule defines a transformation rule
type Rule struct {
	Name        string              `json:"name"`
	Type        TransformType       `json:"type"`
	Condition   Condition           `json:"condition"`
	Actions     []Action            `json:"actions"`
	Priority    int                 `json:"priority"`
	Enabled     bool                `json:"enabled"`
}

// TransformType specifies when the transformation occurs
type TransformType string

const (
	TransformRequest  TransformType = "request"
	TransformResponse TransformType = "response"
	TransformBoth     TransformType = "both"
)

// Condition defines when a rule should be applied
type Condition struct {
	Host        string            `json:"host,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Regex       string            `json:"regex,omitempty"`
}

// Action defines what transformation to perform
type Action struct {
	Type   ActionType             `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// ActionType specifies the type of transformation action
type ActionType string

const (
	// Header transformations
	ActionAddHeader      ActionType = "add_header"
	ActionRemoveHeader   ActionType = "remove_header"
	ActionReplaceHeader  ActionType = "replace_header"
	
	// Path transformations
	ActionRewritePath    ActionType = "rewrite_path"
	ActionStripPrefix    ActionType = "strip_prefix"
	ActionAddPrefix      ActionType = "add_prefix"
	
	// Query transformations
	ActionAddQuery       ActionType = "add_query"
	ActionRemoveQuery    ActionType = "remove_query"
	ActionReplaceQuery   ActionType = "replace_query"
	
	// Body transformations
	ActionReplaceBody    ActionType = "replace_body"
	ActionJSONTransform  ActionType = "json_transform"
	ActionCompress       ActionType = "compress"
	ActionDecompress     ActionType = "decompress"
	
	// Security transformations
	ActionAddCORS        ActionType = "add_cors"
	ActionAddCSP         ActionType = "add_csp"
	ActionSanitizeHTML   ActionType = "sanitize_html"
	ActionRedactSensitive ActionType = "redact_sensitive"
	
	// Response transformations
	ActionCache          ActionType = "cache"
	ActionRateLimit      ActionType = "rate_limit"
	ActionRetry          ActionType = "retry"
)

// NewTransformer creates a new transformer
func NewTransformer() *Transformer {
	return &Transformer{
		rules:           []Rule{},
		enabledFeatures: make(map[string]bool),
	}
}

// AddRule adds a transformation rule
func (t *Transformer) AddRule(rule Rule) {
	t.rules = append(t.rules, rule)
	// Sort by priority
	t.sortRules()
}

// sortRules sorts rules by priority (higher priority first)
func (t *Transformer) sortRules() {
	// Simple bubble sort for now
	for i := 0; i < len(t.rules); i++ {
		for j := i + 1; j < len(t.rules); j++ {
			if t.rules[j].Priority > t.rules[i].Priority {
				t.rules[i], t.rules[j] = t.rules[j], t.rules[i]
			}
		}
	}
}

// TransformRequest applies request transformations
func (t *Transformer) TransformRequest(req *http.Request) error {
	for _, rule := range t.rules {
		if !rule.Enabled {
			continue
		}
		
		if rule.Type != TransformRequest && rule.Type != TransformBoth {
			continue
		}
		
		if !t.matchCondition(req, nil, rule.Condition) {
			continue
		}
		
		for _, action := range rule.Actions {
			if err := t.applyRequestAction(req, action); err != nil {
				logger.Error("Failed to apply request action", 
					"rule", rule.Name,
					"action", action.Type,
					"error", err)
			}
		}
	}
	
	return nil
}

// TransformResponse applies response transformations
func (t *Transformer) TransformResponse(resp *http.Response, req *http.Request) error {
	for _, rule := range t.rules {
		if !rule.Enabled {
			continue
		}
		
		if rule.Type != TransformResponse && rule.Type != TransformBoth {
			continue
		}
		
		if !t.matchCondition(req, resp, rule.Condition) {
			continue
		}
		
		for _, action := range rule.Actions {
			if err := t.applyResponseAction(resp, action); err != nil {
				logger.Error("Failed to apply response action",
					"rule", rule.Name,
					"action", action.Type,
					"error", err)
			}
		}
	}
	
	return nil
}

// matchCondition checks if a condition matches the request/response
func (t *Transformer) matchCondition(req *http.Request, resp *http.Response, cond Condition) bool {
	// Check host
	if cond.Host != "" && req.Host != cond.Host {
		return false
	}
	
	// Check path
	if cond.Path != "" {
		if cond.Regex != "" {
			if matched, _ := regexp.MatchString(cond.Path, req.URL.Path); !matched {
				return false
			}
		} else if !strings.HasPrefix(req.URL.Path, cond.Path) {
			return false
		}
	}
	
	// Check method
	if cond.Method != "" && req.Method != cond.Method {
		return false
	}
	
	// Check headers
	for key, value := range cond.Headers {
		if req.Header.Get(key) != value {
			return false
		}
	}
	
	// Check query params
	for key, value := range cond.QueryParams {
		if req.URL.Query().Get(key) != value {
			return false
		}
	}
	
	return true
}

// applyRequestAction applies an action to a request
func (t *Transformer) applyRequestAction(req *http.Request, action Action) error {
	switch action.Type {
	case ActionAddHeader:
		return t.addHeader(req.Header, action.Config)
	case ActionRemoveHeader:
		return t.removeHeader(req.Header, action.Config)
	case ActionReplaceHeader:
		return t.replaceHeader(req.Header, action.Config)
	case ActionRewritePath:
		return t.rewritePath(req, action.Config)
	case ActionStripPrefix:
		return t.stripPrefix(req, action.Config)
	case ActionAddPrefix:
		return t.addPrefix(req, action.Config)
	case ActionAddQuery:
		return t.addQuery(req, action.Config)
	case ActionRemoveQuery:
		return t.removeQuery(req, action.Config)
	case ActionReplaceQuery:
		return t.replaceQuery(req, action.Config)
	case ActionReplaceBody:
		return t.replaceRequestBody(req, action.Config)
	case ActionJSONTransform:
		return t.transformJSON(req, nil, action.Config)
	case ActionRedactSensitive:
		return t.redactSensitiveData(req, nil, action.Config)
	default:
		return fmt.Errorf("unsupported request action: %s", action.Type)
	}
}

// applyResponseAction applies an action to a response
func (t *Transformer) applyResponseAction(resp *http.Response, action Action) error {
	switch action.Type {
	case ActionAddHeader:
		return t.addHeader(resp.Header, action.Config)
	case ActionRemoveHeader:
		return t.removeHeader(resp.Header, action.Config)
	case ActionReplaceHeader:
		return t.replaceHeader(resp.Header, action.Config)
	case ActionReplaceBody:
		return t.replaceResponseBody(resp, action.Config)
	case ActionJSONTransform:
		return t.transformJSON(nil, resp, action.Config)
	case ActionCompress:
		return t.compressResponse(resp)
	case ActionDecompress:
		return t.decompressResponse(resp)
	case ActionAddCORS:
		return t.addCORS(resp, action.Config)
	case ActionAddCSP:
		return t.addCSP(resp, action.Config)
	case ActionSanitizeHTML:
		return t.sanitizeHTML(resp, action.Config)
	case ActionRedactSensitive:
		return t.redactSensitiveData(nil, resp, action.Config)
	default:
		return fmt.Errorf("unsupported response action: %s", action.Type)
	}
}

// Header transformations

func (t *Transformer) addHeader(headers http.Header, config map[string]interface{}) error {
	name, _ := config["name"].(string)
	value, _ := config["value"].(string)
	
	if name != "" && value != "" {
		headers.Add(name, value)
	}
	
	return nil
}

func (t *Transformer) removeHeader(headers http.Header, config map[string]interface{}) error {
	name, _ := config["name"].(string)
	
	if name != "" {
		headers.Del(name)
	}
	
	return nil
}

func (t *Transformer) replaceHeader(headers http.Header, config map[string]interface{}) error {
	name, _ := config["name"].(string)
	value, _ := config["value"].(string)
	
	if name != "" && value != "" {
		headers.Set(name, value)
	}
	
	return nil
}

// Path transformations

func (t *Transformer) rewritePath(req *http.Request, config map[string]interface{}) error {
	pattern, _ := config["pattern"].(string)
	replacement, _ := config["replacement"].(string)
	
	if pattern != "" && replacement != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		req.URL.Path = re.ReplaceAllString(req.URL.Path, replacement)
	}
	
	return nil
}

func (t *Transformer) stripPrefix(req *http.Request, config map[string]interface{}) error {
	prefix, _ := config["prefix"].(string)
	
	if prefix != "" {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}
	}
	
	return nil
}

func (t *Transformer) addPrefix(req *http.Request, config map[string]interface{}) error {
	prefix, _ := config["prefix"].(string)
	
	if prefix != "" {
		req.URL.Path = prefix + req.URL.Path
	}
	
	return nil
}

// Query transformations

func (t *Transformer) addQuery(req *http.Request, config map[string]interface{}) error {
	params, _ := config["params"].(map[string]interface{})
	
	q := req.URL.Query()
	for key, value := range params {
		q.Add(key, fmt.Sprintf("%v", value))
	}
	req.URL.RawQuery = q.Encode()
	
	return nil
}

func (t *Transformer) removeQuery(req *http.Request, config map[string]interface{}) error {
	keys, _ := config["keys"].([]interface{})
	
	q := req.URL.Query()
	for _, key := range keys {
		q.Del(fmt.Sprintf("%v", key))
	}
	req.URL.RawQuery = q.Encode()
	
	return nil
}

func (t *Transformer) replaceQuery(req *http.Request, config map[string]interface{}) error {
	params, _ := config["params"].(map[string]interface{})
	
	q := req.URL.Query()
	for key, value := range params {
		q.Set(key, fmt.Sprintf("%v", value))
	}
	req.URL.RawQuery = q.Encode()
	
	return nil
}

// Body transformations

func (t *Transformer) replaceRequestBody(req *http.Request, config map[string]interface{}) error {
	body, _ := config["body"].(string)
	
	if body != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	
	return nil
}

func (t *Transformer) replaceResponseBody(resp *http.Response, config map[string]interface{}) error {
	body, _ := config["body"].(string)
	
	if body != "" {
		resp.Body = ioutil.NopCloser(strings.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	
	return nil
}

func (t *Transformer) transformJSON(req *http.Request, resp *http.Response, config map[string]interface{}) error {
	// Read body
	var body io.ReadCloser
	if req != nil {
		body = req.Body
	} else if resp != nil {
		body = resp.Body
	} else {
		return fmt.Errorf("no request or response provided")
	}
	
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}
	
	// Parse JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		// Not JSON, restore body and return
		if req != nil {
			req.Body = ioutil.NopCloser(bytes.NewReader(data))
		} else {
			resp.Body = ioutil.NopCloser(bytes.NewReader(data))
		}
		return nil
	}
	
	// Apply transformations
	if additions, ok := config["add"].(map[string]interface{}); ok {
		for key, value := range additions {
			jsonData[key] = value
		}
	}
	
	if removals, ok := config["remove"].([]interface{}); ok {
		for _, key := range removals {
			delete(jsonData, fmt.Sprintf("%v", key))
		}
	}
	
	// Marshal back to JSON
	newData, err := json.Marshal(jsonData)
	if err != nil {
		return err
	}
	
	// Update body
	if req != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(newData))
		req.ContentLength = int64(len(newData))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(newData)))
	} else {
		resp.Body = ioutil.NopCloser(bytes.NewReader(newData))
		resp.ContentLength = int64(len(newData))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(newData)))
	}
	
	return nil
}

// Compression

func (t *Transformer) compressResponse(resp *http.Response) error {
	// Check if already compressed
	if resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	
	// Read body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	// Compress
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	
	// Update response
	resp.Body = ioutil.NopCloser(&buf)
	resp.ContentLength = int64(buf.Len())
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	
	return nil
}

func (t *Transformer) decompressResponse(resp *http.Response) error {
	encoding := resp.Header.Get("Content-Encoding")
	if encoding != "gzip" {
		return nil
	}
	
	// Create gzip reader
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gr.Close()
	
	// Read decompressed data
	data, err := ioutil.ReadAll(gr)
	if err != nil {
		return err
	}
	
	// Update response
	resp.Body = ioutil.NopCloser(bytes.NewReader(data))
	resp.ContentLength = int64(len(data))
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	
	return nil
}

// Security transformations

func (t *Transformer) addCORS(resp *http.Response, config map[string]interface{}) error {
	origin, _ := config["origin"].(string)
	if origin == "" {
		origin = "*"
	}
	
	resp.Header.Set("Access-Control-Allow-Origin", origin)
	resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	resp.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	resp.Header.Set("Access-Control-Max-Age", "3600")
	
	return nil
}

func (t *Transformer) addCSP(resp *http.Response, config map[string]interface{}) error {
	policy, _ := config["policy"].(string)
	if policy == "" {
		policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
	}
	
	resp.Header.Set("Content-Security-Policy", policy)
	
	return nil
}

func (t *Transformer) sanitizeHTML(resp *http.Response, config map[string]interface{}) error {
	// This would require an HTML sanitization library
	// For now, just add security headers
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("X-XSS-Protection", "1; mode=block")
	
	return nil
}

func (t *Transformer) redactSensitiveData(req *http.Request, resp *http.Response, config map[string]interface{}) error {
	patterns, _ := config["patterns"].([]interface{})
	replacement, _ := config["replacement"].(string)
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	
	for _, pattern := range patterns {
		re, err := regexp.Compile(fmt.Sprintf("%v", pattern))
		if err != nil {
			continue
		}
		
		// Redact headers
		if req != nil {
			for key, values := range req.Header {
				for i, value := range values {
					req.Header[key][i] = re.ReplaceAllString(value, replacement)
				}
			}
		}
		
		if resp != nil {
			for key, values := range resp.Header {
				for i, value := range values {
					resp.Header[key][i] = re.ReplaceAllString(value, replacement)
				}
			}
		}
	}
	
	return nil
}

// LoadRules loads transformation rules from a configuration
func (t *Transformer) LoadRules(rules []Rule) {
	t.rules = rules
	t.sortRules()
}

// GetRules returns all transformation rules
func (t *Transformer) GetRules() []Rule {
	return t.rules
}

// EnableRule enables a specific rule
func (t *Transformer) EnableRule(name string) {
	for i := range t.rules {
		if t.rules[i].Name == name {
			t.rules[i].Enabled = true
			break
		}
	}
}

// DisableRule disables a specific rule
func (t *Transformer) DisableRule(name string) {
	for i := range t.rules {
		if t.rules[i].Name == name {
			t.rules[i].Enabled = false
			break
		}
	}
}

// Middleware returns an HTTP middleware that applies transformations
func (t *Transformer) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply request transformations
			if err := t.TransformRequest(r); err != nil {
				logger.Error("Request transformation failed", "error", err)
			}
			
			// Wrap response writer to capture response
			rw := &responseWriter{
				ResponseWriter: w,
				transformer:    t,
				request:        r,
			}
			
			next.ServeHTTP(rw, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture and transform responses
type responseWriter struct {
	http.ResponseWriter
	transformer *Transformer
	request     *http.Request
	written     bool
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		// Apply response transformations before first write
		// Note: This is simplified; real implementation would need to buffer the response
		rw.written = true
	}
	return rw.ResponseWriter.Write(data)
}