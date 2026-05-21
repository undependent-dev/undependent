# Contributing to Undependent

We welcome contributions! Here's how to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/undependent-dev/undependent.git
cd undependent

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o undep ./cmd/undep
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `go test ./...`
6. Ensure the build is clean: `go build ./...`
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Code Style

- Follow existing patterns in the codebase
- Use `gofmt` for formatting
- Add comments for non-obvious logic
- Keep functions focused and small

## License

By contributing, you agree that your contributions will be licensed under the AGPL v3 license.
