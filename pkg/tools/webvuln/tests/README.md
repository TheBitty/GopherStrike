# Web Vulnerability Scanner Tests

This directory contains tests for the GopherStrike Web Vulnerability Scanner module. The tests verify the functionality of various components of the scanner, including payload generation, scanning logic, and reporting.

## Test Structure

- **main_test.go**: Sets up the test environment and handles test initialization.
- **payload_test.go**: Tests the `PayloadManager` that generates and manages test payloads.
- **models_test.go**: Tests the data structures and options used by the scanner.
- **scanner_test.go**: Tests the core scanning functionality with a mock vulnerable server.
- **integration_test.go**: End-to-end test of the scanner with a more realistic scenario.

## Running Tests

To run all tests:

```
go test
```

To run tests with verbose output:

```
go test -v
```

To run a specific test:

```
go test -run TestScanner -v
```

## Understanding Test Output

The tests create mock HTTP servers with deliberate vulnerabilities and verify that the scanner can detect them. Key vulnerabilities that should be detected include:

1. Cross-Site Scripting (XSS)
2. SQL Injection
3. Cross-Site Request Forgery (CSRF)
4. Security Misconfigurations

When tests pass, it indicates that the scanner is correctly identifying these vulnerabilities in web applications.

## Test Logs

Test logs are stored in the `logs/webvuln_test` directory. These logs can be examined to see detailed scan results and can be useful for debugging.

## Adding New Tests

When adding new tests, consider:

1. Creating a mock server that simulates the vulnerability you want to test
2. Creating test cases that verify the scanner's detection capabilities
3. Verifying both true positives (finding real vulnerabilities) and avoiding false positives

Remember to keep tests fast and focused - each test should verify a specific aspect of the scanner. 