package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"html/template"

	"github.com/russross/blackfriday/v2"
)

// VulnerabilitySeverity represents the severity level of a vulnerability
type VulnerabilitySeverity string

const (
	SeverityCritical VulnerabilitySeverity = "Critical"
	SeverityHigh     VulnerabilitySeverity = "High"
	SeverityMedium   VulnerabilitySeverity = "Medium"
	SeverityLow      VulnerabilitySeverity = "Low"
	SeverityInfo     VulnerabilitySeverity = "Info"
)

// VulnerabilityStatus represents the status of a vulnerability
type VulnerabilityStatus string

const (
	StatusOpen       VulnerabilityStatus = "Open"
	StatusConfirmed  VulnerabilityStatus = "Confirmed"
	StatusDuplicate  VulnerabilityStatus = "Duplicate"
	StatusFixed      VulnerabilityStatus = "Fixed"
	StatusInProgress VulnerabilityStatus = "In Progress"
)

// Evidence represents evidence for a vulnerability
type Evidence struct {
	Description string
	Type        string // screenshot, request, response, code
	Data        string // file path or actual content
}

// Vulnerability represents a vulnerability finding
type Vulnerability struct {
	Title           string
	Description     string
	Severity        VulnerabilitySeverity
	Status          VulnerabilityStatus
	CWE             string
	CVSS            float64
	AffectedTargets []string
	Steps           []string
	Evidence        []Evidence
	Impact          string
	Remediation     string
	References      []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Tags            []string
}

// ReportOptions represents options for report generation
type ReportOptions struct {
	Title               string
	Format              string // markdown, html, pdf
	TemplateFile        string
	OutputFile          string
	IncludeExecutive    bool
	IncludeTechnical    bool
	IncludeRemediation  bool
	IncludeEvidence     bool
	CompanyName         string
	LogoPath            string
	AuthorName          string
	ConfidentialityNote string
	CustomCSS           string
}

// DefaultReportOptions returns default report options
func DefaultReportOptions() ReportOptions {
	return ReportOptions{
		Title:               "Security Assessment Report",
		Format:              "markdown",
		TemplateFile:        "",
		OutputFile:          "reports/security_report.md",
		IncludeExecutive:    true,
		IncludeTechnical:    true,
		IncludeRemediation:  true,
		IncludeEvidence:     true,
		CompanyName:         "GopherStrike Security",
		LogoPath:            "",
		AuthorName:          "",
		ConfidentialityNote: "CONFIDENTIAL - FOR INTERNAL USE ONLY",
		CustomCSS:           "",
	}
}

// Report represents a vulnerability report
type Report struct {
	Options         ReportOptions
	Vulnerabilities []Vulnerability
	GeneratedAt     time.Time
	SeverityCounts  map[VulnerabilitySeverity]int
	TargetScope     []string
	Summary         string
	BodyHTML        string
}

// ReportGenerator handles report generation
type ReportGenerator struct {
	options         ReportOptions
	vulnerabilities []Vulnerability
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(options ReportOptions) *ReportGenerator {
	return &ReportGenerator{
		options:         options,
		vulnerabilities: []Vulnerability{},
	}
}

// AddVulnerability adds a vulnerability to the report
func (r *ReportGenerator) AddVulnerability(vuln Vulnerability) {
	// Set timestamps if not set
	if vuln.CreatedAt.IsZero() {
		vuln.CreatedAt = time.Now()
	}
	if vuln.UpdatedAt.IsZero() {
		vuln.UpdatedAt = time.Now()
	}

	r.vulnerabilities = append(r.vulnerabilities, vuln)
}

// GenerateReport generates a report based on the options and vulnerabilities
func (r *ReportGenerator) GenerateReport() (*Report, error) {
	report := &Report{
		Options:         r.options,
		Vulnerabilities: r.vulnerabilities,
		GeneratedAt:     time.Now(),
		SeverityCounts:  make(map[VulnerabilitySeverity]int),
		TargetScope:     []string{},
	}

	// Calculate severity counts
	for _, vuln := range r.vulnerabilities {
		report.SeverityCounts[vuln.Severity]++

		// Collect unique targets
		for _, target := range vuln.AffectedTargets {
			found := false
			for _, existingTarget := range report.TargetScope {
				if existingTarget == target {
					found = true
					break
				}
			}
			if !found {
				report.TargetScope = append(report.TargetScope, target)
			}
		}
	}

	// Generate summary
	report.Summary = r.generateSummary(report)

	return report, nil
}

// generateSummary generates a summary of the findings
func (r *ReportGenerator) generateSummary(report *Report) string {
	totalVulns := len(report.Vulnerabilities)
	if totalVulns == 0 {
		return "No vulnerabilities were found during the assessment."
	}

	summary := fmt.Sprintf("A total of %d vulnerabilities were identified during the assessment. ", totalVulns)

	// Add severity breakdown
	severities := []VulnerabilitySeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	counts := []string{}

	for _, severity := range severities {
		count := report.SeverityCounts[severity]
		if count > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", count, severity))
		}
	}

	if len(counts) > 0 {
		summary += "Breakdown by severity: " + strings.Join(counts, ", ") + "."
	}

	return summary
}

// SaveReport saves the report to a file in the specified format
func (r *ReportGenerator) SaveReport(report *Report) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(report.Options.OutputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Generate content based on format
	var content string
	var err error

	switch strings.ToLower(report.Options.Format) {
	case "markdown":
		content, err = r.generateMarkdownReport(report)
	case "html":
		content, err = r.generateHTMLReport(report)
	default:
		return fmt.Errorf("unsupported report format: %s", report.Options.Format)
	}

	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(report.Options.OutputFile, []byte(content), 0644)
}

// generateMarkdownReport generates a Markdown report
func (r *ReportGenerator) generateMarkdownReport(report *Report) (string, error) {
	var content strings.Builder

	// Title and header
	content.WriteString(fmt.Sprintf("# %s\n\n", report.Options.Title))
	content.WriteString(fmt.Sprintf("**Date:** %s\n\n", report.GeneratedAt.Format("January 2, 2006")))

	if report.Options.CompanyName != "" {
		content.WriteString(fmt.Sprintf("**Prepared by:** %s\n\n", report.Options.CompanyName))
	}

	if report.Options.AuthorName != "" {
		content.WriteString(fmt.Sprintf("**Author:** %s\n\n", report.Options.AuthorName))
	}

	if report.Options.ConfidentialityNote != "" {
		content.WriteString(fmt.Sprintf("**%s**\n\n", report.Options.ConfidentialityNote))
	}

	// Table of Contents
	content.WriteString("## Table of Contents\n\n")
	content.WriteString("1. [Executive Summary](#executive-summary)\n")
	content.WriteString("2. [Scope](#scope)\n")
	content.WriteString("3. [Findings Summary](#findings-summary)\n")
	content.WriteString("4. [Vulnerability Details](#vulnerability-details)\n")
	if report.Options.IncludeRemediation {
		content.WriteString("5. [Remediation Summary](#remediation-summary)\n")
	}
	content.WriteString("\n")

	// Executive Summary
	if report.Options.IncludeExecutive {
		content.WriteString("## Executive Summary\n\n")
		content.WriteString(report.Summary + "\n\n")

		// Add severity chart in Markdown
		content.WriteString("### Severity Breakdown\n\n")
		content.WriteString("| Severity | Count |\n")
		content.WriteString("|----------|-------|\n")

		severities := []VulnerabilitySeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
		for _, severity := range severities {
			count := report.SeverityCounts[severity]
			content.WriteString(fmt.Sprintf("| %s | %d |\n", severity, count))
		}

		content.WriteString("\n")
	}

	// Scope
	content.WriteString("## Scope\n\n")
	if len(report.TargetScope) > 0 {
		content.WriteString("The assessment covered the following targets:\n\n")
		for _, target := range report.TargetScope {
			content.WriteString(fmt.Sprintf("* %s\n", target))
		}
	} else {
		content.WriteString("No specific targets were identified in this report.\n")
	}
	content.WriteString("\n")

	// Findings Summary
	content.WriteString("## Findings Summary\n\n")
	if len(report.Vulnerabilities) > 0 {
		content.WriteString("| # | Title | Severity | Status |\n")
		content.WriteString("|---|-------|----------|--------|\n")

		for i, vuln := range report.Vulnerabilities {
			content.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n",
				i+1, vuln.Title, vuln.Severity, vuln.Status))
		}
	} else {
		content.WriteString("No vulnerabilities were found during the assessment.\n")
	}
	content.WriteString("\n")

	// Vulnerability Details
	content.WriteString("## Vulnerability Details\n\n")

	for i, vuln := range report.Vulnerabilities {
		content.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, vuln.Title))

		// Basic info table
		content.WriteString("| Attribute | Value |\n")
		content.WriteString("|-----------|-------|\n")
		content.WriteString(fmt.Sprintf("| Severity | %s |\n", vuln.Severity))
		content.WriteString(fmt.Sprintf("| Status | %s |\n", vuln.Status))

		if vuln.CWE != "" {
			content.WriteString(fmt.Sprintf("| CWE | %s |\n", vuln.CWE))
		}

		if vuln.CVSS > 0 {
			content.WriteString(fmt.Sprintf("| CVSS | %.1f |\n", vuln.CVSS))
		}

		content.WriteString("\n")

		// Description
		content.WriteString("#### Description\n\n")
		content.WriteString(vuln.Description + "\n\n")

		// Affected Targets
		if len(vuln.AffectedTargets) > 0 {
			content.WriteString("#### Affected Targets\n\n")
			for _, target := range vuln.AffectedTargets {
				content.WriteString(fmt.Sprintf("* %s\n", target))
			}
			content.WriteString("\n")
		}

		// Steps to Reproduce
		if len(vuln.Steps) > 0 {
			content.WriteString("#### Steps to Reproduce\n\n")
			for j, step := range vuln.Steps {
				content.WriteString(fmt.Sprintf("%d. %s\n", j+1, step))
			}
			content.WriteString("\n")
		}

		// Evidence
		if report.Options.IncludeEvidence && len(vuln.Evidence) > 0 {
			content.WriteString("#### Evidence\n\n")
			for j, evidence := range vuln.Evidence {
				content.WriteString(fmt.Sprintf("##### Evidence %d: %s\n\n", j+1, evidence.Description))

				if evidence.Type == "screenshot" {
					content.WriteString(fmt.Sprintf("![Screenshot](%s)\n\n", evidence.Data))
				} else {
					content.WriteString("```\n" + evidence.Data + "\n```\n\n")
				}
			}
		}

		// Impact
		if vuln.Impact != "" {
			content.WriteString("#### Impact\n\n")
			content.WriteString(vuln.Impact + "\n\n")
		}

		// Remediation
		if report.Options.IncludeRemediation && vuln.Remediation != "" {
			content.WriteString("#### Remediation\n\n")
			content.WriteString(vuln.Remediation + "\n\n")
		}

		// References
		if len(vuln.References) > 0 {
			content.WriteString("#### References\n\n")
			for _, ref := range vuln.References {
				content.WriteString(fmt.Sprintf("* %s\n", ref))
			}
			content.WriteString("\n")
		}
	}

	// Remediation Summary
	if report.Options.IncludeRemediation {
		content.WriteString("## Remediation Summary\n\n")

		// Group vulnerabilities by severity for remediation prioritization
		content.WriteString("### Prioritization\n\n")
		content.WriteString("Remediation efforts should be prioritized based on vulnerability severity:\n\n")

		severities := []VulnerabilitySeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
		for _, severity := range severities {
			if report.SeverityCounts[severity] > 0 {
				content.WriteString(fmt.Sprintf("#### %s Severity Issues\n\n", severity))

				for _, vuln := range report.Vulnerabilities {
					if vuln.Severity == severity {
						content.WriteString(fmt.Sprintf("* **%s**: %s\n", vuln.Title, vuln.Remediation))
					}
				}
				content.WriteString("\n")
			}
		}
	}

	return content.String(), nil
}

// generateHTMLReport generates an HTML report
func (r *ReportGenerator) generateHTMLReport(report *Report) (string, error) {
	// First generate markdown
	markdown, err := r.generateMarkdownReport(report)
	if err != nil {
		return "", err
	}

	// Convert markdown to HTML
	html := blackfriday.Run([]byte(markdown))

	// Create HTML document with basic styling
	templateStr := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1100px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #2c3e50;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        h3 {
            color: #3498db;
            margin-top: 25px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            color: #333;
        }
        .severity-Critical {
            background-color: #ffdddd;
            color: #c00000;
        }
        .severity-High {
            background-color: #ffeecc;
            color: #e67e00;
        }
        .severity-Medium {
            background-color: #ffffcc;
            color: #827700;
        }
        .severity-Low {
            background-color: #e6ffe6;
            color: #006600;
        }
        .severity-Info {
            background-color: #e6f2ff;
            color: #0066cc;
        }
        code {
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: monospace;
        }
        .footer {
            margin-top: 40px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            font-size: 0.9em;
            color: #777;
        }
        {{.CustomCSS}}
    </style>
</head>
<body>
    <div class="content">
        {{.Content}}
    </div>
    <div class="footer">
        <p>Generated by GopherStrike Security Reporting Tool on {{.Date}}</p>
    </div>
</body>
</html>`

	// Create template data
	data := struct {
		Title     string
		Content   string
		Date      string
		CustomCSS string
	}{
		Title:     report.Options.Title,
		Content:   string(html),
		Date:      report.GeneratedAt.Format("January 2, 2006"),
		CustomCSS: report.Options.CustomCSS,
	}

	// Execute template
	tmpl, err := template.New("report").Parse(templateStr)
	if err != nil {
		return "", err
	}

	var output strings.Builder
	err = tmpl.Execute(&output, data)
	if err != nil {
		return "", err
	}

	return output.String(), nil
}

// RunReportGenerator is the main entry point for the report generator
func RunReportGenerator() error {
	fmt.Println("\n[+] Vulnerability Report Generator")
	fmt.Println("    ============================")

	// Configure options
	options := DefaultReportOptions()

	// Get report title
	fmt.Printf("[?] Report title (default: %s): ", options.Title)
	var title string
	fmt.Scanln(&title)
	if title != "" {
		options.Title = title
	}

	// Get output format
	fmt.Print("[?] Output format (markdown/html) [default: markdown]: ")
	var format string
	fmt.Scanln(&format)
	if format != "" {
		options.Format = strings.ToLower(format)
	}

	// Get output file
	defaultExt := ".md"
	if options.Format == "html" {
		defaultExt = ".html"
	}
	defaultOutput := fmt.Sprintf("reports/security_report%s", defaultExt)

	fmt.Printf("[?] Output file (default: %s): ", defaultOutput)
	var outputFile string
	fmt.Scanln(&outputFile)
	if outputFile != "" {
		options.OutputFile = outputFile
	} else {
		options.OutputFile = defaultOutput
	}

	// Get company name
	fmt.Printf("[?] Company name (default: %s): ", options.CompanyName)
	var companyName string
	fmt.Scanln(&companyName)
	if companyName != "" {
		options.CompanyName = companyName
	}

	// Get author name
	fmt.Print("[?] Author name: ")
	fmt.Scanln(&options.AuthorName)

	// Create report generator
	reportGen := NewReportGenerator(options)

	// Add some sample vulnerabilities for demonstration
	// In a real implementation, these would be loaded from scan results
	fmt.Print("[?] Do you want to include sample vulnerabilities for demonstration? (Y/n): ")
	var includeSamples string
	fmt.Scanln(&includeSamples)

	if includeSamples == "" || strings.ToLower(includeSamples) == "y" {
		// Add sample SQL Injection vulnerability
		sqlInjection := Vulnerability{
			Title:       "SQL Injection in Login Form",
			Description: "A SQL injection vulnerability was discovered in the login form. An attacker can inject malicious SQL queries that may allow unauthorized access to the database.",
			Severity:    SeverityHigh,
			Status:      StatusOpen,
			CWE:         "CWE-89",
			CVSS:        7.5,
			AffectedTargets: []string{
				"https://example.com/login.php",
			},
			Steps: []string{
				"Navigate to the login page at https://example.com/login.php",
				"Enter `' OR 1=1 --` in the username field",
				"Enter any value in the password field",
				"Click the login button",
				"Observe that the application grants access without valid credentials",
			},
			Evidence: []Evidence{
				{
					Description: "Request with SQL Injection payload",
					Type:        "request",
					Data:        "POST /login.php HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=' OR 1=1 --&password=test",
				},
			},
			Impact:      "This vulnerability allows attackers to bypass authentication and access sensitive user data. It could lead to unauthorized access, data breach, and account takeover.",
			Remediation: "Implement prepared statements or parameterized queries to ensure that user input is not directly included in SQL queries. Additionally, implement input validation and use an ORM where possible.",
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
				"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
			},
		}
		reportGen.AddVulnerability(sqlInjection)

		// Add sample XSS vulnerability
		xss := Vulnerability{
			Title:       "Stored Cross-Site Scripting (XSS) in Comment Section",
			Description: "A stored XSS vulnerability was identified in the comment section of the blog posts. Attackers can inject malicious JavaScript that executes in visitors' browsers.",
			Severity:    SeverityMedium,
			Status:      StatusOpen,
			CWE:         "CWE-79",
			CVSS:        6.1,
			AffectedTargets: []string{
				"https://example.com/blog/post/123",
			},
			Steps: []string{
				"Navigate to any blog post",
				"Submit a comment containing the payload: `<script>alert(document.cookie)</script>`",
				"View the blog post again",
				"Observe that the JavaScript executes and shows an alert with cookies",
			},
			Evidence: []Evidence{
				{
					Description: "JavaScript execution in browser",
					Type:        "screenshot",
					Data:        "evidence/xss_screenshot.png",
				},
			},
			Impact:      "This vulnerability allows attackers to steal users' session cookies, perform actions on behalf of the victim, and potentially lead to account takeover.",
			Remediation: "Implement proper output encoding when displaying user-generated content. Use a Content Security Policy (CSP) to restrict the execution of scripts. Consider using a security library like DOMPurify to sanitize HTML content.",
			References: []string{
				"https://owasp.org/www-community/attacks/xss/",
				"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			},
		}
		reportGen.AddVulnerability(xss)

		// Add sample Information Disclosure vulnerability
		infoDisclosure := Vulnerability{
			Title:       "Sensitive Information Disclosure in HTTP Headers",
			Description: "The application reveals sensitive information in HTTP headers, including server version, framework details, and internal IP addresses.",
			Severity:    SeverityLow,
			Status:      StatusOpen,
			CWE:         "CWE-200",
			CVSS:        3.7,
			AffectedTargets: []string{
				"https://example.com",
				"https://api.example.com",
			},
			Steps: []string{
				"Send a request to the target domain",
				"Observe the response headers",
				"Note the presence of detailed server and technology information",
			},
			Evidence: []Evidence{
				{
					Description: "HTTP Response Headers",
					Type:        "response",
					Data:        "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3\nX-AspNet-Version: 4.0.30319\nX-Internal-IP: 10.0.0.15\nContent-Type: text/html",
				},
			},
			Impact:      "This information helps attackers target specific vulnerabilities in the revealed software versions and may assist in more sophisticated attacks.",
			Remediation: "Configure the web server to remove or obfuscate sensitive headers. For Apache, use the `ServerTokens Prod` and `ServerSignature Off` directives. For nginx, set `server_tokens off`. Remove custom headers that reveal internal information.",
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
			},
		}
		reportGen.AddVulnerability(infoDisclosure)
	}

	// Generate and save report
	report, err := reportGen.GenerateReport()
	if err != nil {
		return err
	}

	err = reportGen.SaveReport(report)
	if err != nil {
		return err
	}

	fmt.Printf("\n[+] Report generated successfully: %s\n", report.Options.OutputFile)
	return nil
}
