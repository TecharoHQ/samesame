# samesame

The Web Bot Auth implementation for Anubis.

## Overview

A Go library providing basic arithmetic operations.

## Installation

```bash
go get github.com/TecharoHQ/samesame
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/TecharoHQ/samesame"
)

func main() {
    result := samesame.Add(2, 3)
    fmt.Println(result) // Output: 5
}
```

## Development

This project uses the following tools:

- **Go**: Programming language
- **goimports**: Automatic import formatting
- **commitlint**: Commit message linting
- **prettier**: Code formatting for JS/JSON/Markdown files
- **husky**: Git hooks management

### Prerequisites

- Go 1.24+ installed
- Node.js and npm installed

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

### Available Scripts

- `npm run test` - Run Go tests
- `npm run fmt` - Format all code (Go and JS/JSON/Markdown)
- `npm run lint` - Run Go vet for static analysis

### Pre-commit Hooks

The project includes pre-commit hooks that automatically:

- Format Go code with goimports and go fmt
- Run go vet for static analysis
- Run all tests
- Format JavaScript, JSON, and Markdown files with prettier

### Commit Message Format

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification. Commit messages must be in the format:

```
<type>: <description>
```

Example: `feat: add new authentication method`

Valid types: feat, fix, docs, style, refactor, test, chore, etc.
