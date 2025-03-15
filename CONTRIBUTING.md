# Contributing to GopherStrike

First off, thank you for considering contributing to GopherStrike! It's people like you that make GopherStrike such a great tool.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for GopherStrike. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

**Before Submitting A Bug Report:**

* Check the [issues](https://github.com/yourusername/GopherStrike/issues) to see if the problem has already been reported. If it has and the issue is still open, add a comment to the existing issue instead of opening a new one.
* Determine which repository the problem should be reported in.

**How Do I Submit A (Good) Bug Report?**

Bugs are tracked as [GitHub issues](https://github.com/yourusername/GopherStrike/issues). Create an issue and provide the following information:

* Use a clear and descriptive title for the issue to identify the problem.
* Describe the exact steps which reproduce the problem in as many details as possible.
* Provide specific examples to demonstrate the steps.
* Describe the behavior you observed after following the steps and point out what exactly is the problem with that behavior.
* Explain which behavior you expected to see instead and why.
* Include screenshots and animated GIFs which show you following the described steps and clearly demonstrate the problem.
* If the problem wasn't triggered by a specific action, describe what you were doing before the problem happened.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for GopherStrike, including completely new features and minor improvements to existing functionality.

**Before Submitting An Enhancement Suggestion:**

* Check if the enhancement has already been suggested.
* Determine which repository the enhancement should be suggested in.

**How Do I Submit A (Good) Enhancement Suggestion?**

Enhancement suggestions are tracked as [GitHub issues](https://github.com/yourusername/GopherStrike/issues). Create an issue and provide the following information:

* Use a clear and descriptive title for the issue to identify the suggestion.
* Provide a step-by-step description of the suggested enhancement in as many details as possible.
* Provide specific examples to demonstrate the steps or point out the part of GopherStrike which the suggestion is related to.
* Describe the current behavior and explain which behavior you expected to see instead and why.
* Explain why this enhancement would be useful to most GopherStrike users.
* List some other tools or applications where this enhancement exists.

### Pull Requests

* Fill in the required template
* Do not include issue numbers in the PR title
* Include screenshots and animated GIFs in your pull request whenever possible
* Follow the Go styleguides
* Include tests when adding new features
* Update documentation when changing the API

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* Consider starting the commit message with an applicable emoji:
    * 🎨 `:art:` when improving the format/structure of the code
    * 🐎 `:racehorse:` when improving performance
    * 🚱 `:non-potable_water:` when plugging memory leaks
    * 📝 `:memo:` when writing docs
    * 🐛 `:bug:` when fixing a bug
    * 🔥 `:fire:` when removing code or files
    * 💚 `:green_heart:` when fixing the CI build
    * ✅ `:white_check_mark:` when adding tests
    * 🔒 `:lock:` when dealing with security
    * ⬆️ `:arrow_up:` when upgrading dependencies
    * ⬇️ `:arrow_down:` when downgrading dependencies

### Go Styleguide

* Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
* Format your code with `gofmt`
* Document all public functions and types
* Use meaningful variable names
* Keep functions small and focused
* Write tests for your code

## Development Setup

Here's how to set up GopherStrike for local development:

1. Fork the GopherStrike repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/GopherStrike.git
   cd GopherStrike
   ```
3. Create a branch for local development:
   ```bash
   git checkout -b name-of-your-bugfix-or-feature
   ```
4. Make your changes locally.
5. Run tests to make sure your changes don't break existing functionality:
   ```bash
   go test ./...
   ```
6. Commit your changes and push your branch to GitHub:
   ```bash
   git add .
   git commit -m "Your detailed description of your changes"
   git push origin name-of-your-bugfix-or-feature
   ```
7. Submit a pull request through the GitHub website.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations, and container parameters.
3. Increase the version numbers in any examples files and the README.md to the new version that this Pull Request would represent.
4. The pull request will be merged once you have the sign-off of at least one maintainer.

## Community

Join our community to discuss GopherStrike development:

* [Discord](https://discord.gg/yourdiscordlink)
* [Twitter](https://twitter.com/yourtwitterhandle)

## Attribution

This Contributing Guide is adapted from the [Atom Contributing Guide](https://github.com/atom/atom/blob/master/CONTRIBUTING.md). 