# Go Project Structure — Clean Architecture Guide

## Core principle

Dependencies flow inward. Outer layers know about inner layers. Inner layers know nothing about outer layers.

```
main → cmd → internal → domain types
```

Nothing reverses this direction.

---

## Layer responsibilities

### `main.go`
Single job: bootstrap and hand off.

```go
func main() {
    ctx := signalContext()
    err := cmd.Execute(ctx)
    os.Exit(exitcode.FromError(err))
}
```

No logic. No flags. No formatting.

---

### `cmd/`
Translates CLI inputs into internal function calls.

**Contains:**
- Cobra command definitions and flag registration
- Dependency wiring (constructing structs from config/flags)
- Calling into `internal/`
- Mapping returned errors to exit codes

**Does not contain:**
- Algorithms
- Business rules
- Anything you'd want to unit test in isolation

The test for whether something belongs here: *can it only be tested by invoking a Cobra command?* If yes, it's fine in `cmd/`. If no — if it's a pure function or self-contained logic — it belongs in `internal/`.

---

### `internal/`
All real work. Organized by domain or capability, not by technical role.

**DO:**
```
internal/
├── client/      # external API communication
├── parser/      # input parsing
├── cache/       # caching layer
├── output/      # formatting / rendering
├── config/      # configuration loading
└── osmerr/      # error vocabulary
```

**DON'T:**
```
internal/
├── handlers/    # technical role — not a domain
├── models/      # technical role — not a domain
└── services/    # technical role — not a domain
```

Each package should be answerable by one sentence: *"this package does X."* If you need "and" — split it.

---

### Domain types
Shared types that multiple packages use should have no dependencies on other internal packages.

```go
// internal/domain/types.go
type Package struct {
    Name      string
    Version   string
    Ecosystem string
}
```

If you find `parser` importing `client` to share a type, that's a signal to extract the type into a neutral package.

---

## Interfaces

Define interfaces at the consumer, not the producer.

```go
// in the package that needs it, not the package that implements it
type Lookup interface {
    Check(ctx context.Context, q Query) (*Result, error)
}
```

This means `internal/client` returns a concrete `*Client`. The package that calls it defines a `Lookup` interface if it needs one. `*Client` satisfies it structurally — no explicit declaration needed.

Keep interfaces small. One to three methods. If your interface has eight methods, it's describing an implementation, not a capability.

---

## Testing

**Co-locate tests with source:**
```
internal/parser/
├── parser.go
├── parser_test.go
├── npm_packagejson.go
├── npm_packagejson_test.go
└── testdata/
    ├── pkg_basic.json
    └── pkg_malformed.json
```

**Use build tags to separate integration tests:**
```go
//go:build integration
```

```bash
go test ./...                          # unit tests only
go test -tags integration ./tests/...  # integration tests
```

**Two test package styles:**
```go
package parser        // white-box: can access unexported identifiers
package parser_test   // black-box: tests exported surface only
```

Use white-box for testing internals. Use black-box for testing the contract your package makes with the outside world.

---

## Dependency injection

No globals. No `init()`. Constructor injection throughout.

```go
// build the graph explicitly, in order
store   := storage.New(db)
cache   := cache.New(store)
client  := client.New(cfg.Token, cache)
```

Each constructor takes what it needs as arguments. The full graph is assembled once, at the top — in `main.go` or in a dedicated `deps` struct in `cmd/`.

---

## The test for a good structure

Ask these questions:

1. **Can I test this package without invoking a CLI command?** If no, the logic is too high up.
2. **Does this package import anything it shouldn't know about?** `parser` shouldn't import `client`. `output` shouldn't import `cache`.
3. **Can I describe what this package does in one sentence without using "and"?**
4. **If I delete this package, does anything in `internal/` break?** If `cmd/` disappears and `internal/` still compiles, your boundaries are clean.
5. **Where does business logic change most often?** That code should be deepest in `internal/`, furthest from Cobra, most directly testable.

---

## What this is not

This is not a rule that `cmd/` must be five lines. Orchestration — fan-out, error collection, result ordering — is legitimately a command-layer concern when it exists to serve the CLI's output contract. The line is: *does moving this to `internal/` make it more testable and more reusable, with no coupling cost?* If yes, move it. If no, leave it.
