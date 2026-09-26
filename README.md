# grounds

A monorepo of [Bend 2](https://github.com/bendlang/bend) packages, built with [moon](https://moonrepo.dev).

| Package | Does |
|---|---|
| [`json`](json/) | JSON parser and printer, proven to round-trip; to be published as `grounds-json` |

```sh
mise install              # the pinned bend and moon
moon run json:check       # every test, law and conformance case of json
moon run json:bench       # json against Go, jq, Python, Node and Bun
```

Each package is a moon project (`<package>/moon.yml`); `.moon/workspace.yml` lists them.
