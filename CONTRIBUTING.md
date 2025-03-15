# Contributing to GopherStrike

Thank you for considering contributing to GopherStrike! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Project Structure](#project-structure)
  - [Development Environment](#development-environment)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Style Guidelines](#style-guidelines)
  - [Code Style](#code-style)
  - [Commit Messages](#commit-messages)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Project Structure

The GopherStrike project is organized as follows:

```
GopherStrike/
├── .github/           # GitHub specific files (workflows, issue templates)
├── assets/            # Project assets (images, logos, etc.)
├── cmd/               # Command-line interface code
├── pkg/               # Core packages
│   ├── tools/         # Individual security tools
│   ├── logging/       # Logging functionality
│   └── ...            # Other packages
├── utils/             # Utility functions
├── docs/              # Documentation
├── tests/             # Tests
├── go.mod             # Go module file
├── go.sum             # Go module checksum
├── main.go            # Application entry point
├── LICENSE            # License file
└── README.md          # Project overview
```

### Development Environment

To set up your development environment:

1. Install Go 1.16 or higher
2. Install Git
3. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/GopherStrike.git
   cd GopherStrike
   ```
4. Install dependencies:
   ```bash
   go mod download
   ```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the [issue tracker](https://github.com/yourusername/GopherStrike/issues) to see if the problem has already been reported. If it has and the issue is still open, add a comment to the existing issue instead of opening a new one.

When creating a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps which reproduce the problem**
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead**
- **Include screenshots if possible**
- **Include details about your configuration and environment**

### Suggesting Enhancements

Enhancement suggestions are tracked as [GitHub issues](https://github.com/yourusername/GopherStrike/issues). When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the proposed enhancement**
- **Explain why this enhancement would be useful**
- **List any alternatives you've considered**
- **Include any relevant examples or mockups**

### Pull Requests

1. **Fork the repository**
2. **Create a new branch** for your feature or bugfix: `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Run tests** to ensure your changes don't break existing functionality
5. **Commit your changes** with clear commit messages
6. **Push to your fork**: `git push origin feature/your-feature-name`
7. **Open a pull request** against the `main` branch

## Style Guidelines

### Code Style

- Follow the standard Go code style and conventions
- Use `gofmt` to format your code
- Follow the [Effective Go](https://golang.org/doc/effective_go) principles
- Use meaningful variable and function names
- Write comments for complex or non-obvious code sections

### Commit Messages

- Use clear and descriptive commit messages
- Start with a short summary (50 chars or less)
- Optionally followed by a blank line and a more detailed explanation
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")

## Testing

- Write tests for all new features and bug fixes
- Ensure existing tests pass before submitting a PR
- Aim for good code coverage

To run tests:

```bash
go test ./...
```

## Documentation

- Update the README.md with details of changes to the interface
- Update the documentation when adding or changing features
- Use godoc style comments for packages and exported functions

## Community

- Join our [Discord server](https://discord.gg/yourinvitelink) for discussions
- Follow the project on Twitter: [@GopherStrike](https://twitter.com/yourusername)
- Subscribe to our mailing list for updates

Thank you for contributing to GopherStrike! 