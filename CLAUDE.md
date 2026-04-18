# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev       # tsx watch src/index.ts (hot reload)
npm run build     # tsc -> dist/
npm start         # node dist/index.js (run built server)
npm run lint      # eslint "src/**/*.ts"
npm run format    # prettier --write .
npx playwright install   # required once to install browser binaries
```

Tests are ad-hoc Node scripts that import the **built** `dist/` output. Run `npm run build` first, then execute individually:

```bash
node tests/test-search.js        # tries full multi-engine fallback chain
node tests/test-bing.js          # isolate a single engine
node tests/test-all-engines.js
```

There is no test runner (no Jest/Vitest), no CI-invoked test script, and no `npm test`. `scripts/bundle.js` is an esbuild single-file bundler — **not** wired into `npm run build`; `tsc` is the shipping build.

## Architecture

This is an MCP (Model Context Protocol) stdio server exposing three tools to local LLM clients (LM Studio, LibreChat). Everything is a single-process Node app; there is no HTTP surface.

**Entry point** — [src/index.ts](src/index.ts) constructs `WebSearchMCPServer`, registers three tools on `McpServer` from `@modelcontextprotocol/sdk`, and connects via `StdioServerTransport`. All tool input validation lives inline in `index.ts` (Zod schemas + hand-written `validateAndConvertArgs`), because some LLMs send stringified numbers/booleans and the validators coerce them. The `isLikelyLlama` / `isLikelyRobustModel` heuristic in `full-web-search` auto-caps `maxContentLength` based on whether args arrived as strings vs native types — this is load-bearing model-compatibility logic, not dead code.

**Two-layer search pipeline:**

1. [src/search-engine.ts](src/search-engine.ts) — `SearchEngine.search()` runs a fallback chain: Browser Bing → Browser Brave → Axios DuckDuckGo. Each attempt gets scored by `assessResultQuality()`; the loop short-circuits on quality ≥ 0.8 or a threshold hit past the first engine, otherwise returns the best of all attempts. `FORCE_MULTI_ENGINE_SEARCH=true` disables short-circuiting. Rate-limited via [src/rate-limiter.ts](src/rate-limiter.ts) (10 req/min).

2. [src/enhanced-content-extractor.ts](src/enhanced-content-extractor.ts) — `EnhancedContentExtractor.extractContent()` tries axios first (fast), then falls back to Playwright browser on signals like bot-detection / HTTP/2 errors (`shouldUseBrowser`). `extractContentForResults()` runs extraction for an over-fetched result set concurrently via `p-limit`, stopping once `limit` successes accumulate. PDFs are detected by `isPdfUrl` in [src/utils.ts](src/utils.ts) and skipped — `full-web-search` requests `min(limit*2+2, 10)` results upstream to compensate.

**Shared browser pool** — [src/browser-pool.ts](src/browser-pool.ts) `BrowserPool` is instantiated **independently** by both `SearchEngine` and `EnhancedContentExtractor` (not shared). It rotates through `BROWSER_TYPES` (default chromium,firefox), health-checks cached browsers before reuse, and is explicitly closed via `closeAll()` on each tool invocation and on SIGINT/SIGTERM. `get-web-search-summaries` wraps its search in `try/finally` with `closeAll()` specifically to prevent EventEmitter listener leaks when browsers accumulate across short-lived calls — don't remove that cleanup.

**Type contracts** live in [src/types.ts](src/types.ts). `SearchResult` is the unified shape flowing through both layers; fields like `fullContent`, `wordCount`, `fetchStatus`, `error` are populated by the extractor, not the search engine.

## Environment variables that change behavior

Documented in [README.md](README.md). The ones most likely to matter when debugging:

- `MAX_CONTENT_LENGTH` (default 500000), `DEFAULT_TIMEOUT` (6000 ms)
- `MAX_BROWSERS` (3), `BROWSER_TYPES` (`chromium,firefox`), `BROWSER_HEADLESS` (true), `BROWSER_FALLBACK_THRESHOLD` (3)
- `ENABLE_RELEVANCE_CHECKING` (true), `RELEVANCE_THRESHOLD` (0.3), `FORCE_MULTI_ENGINE_SEARCH` (false)
- `DEBUG_BROWSER_LIFECYCLE` (false) — turn on when browsers hang or leak

## Repository conventions

- ESM (`"type": "module"`). Relative imports **must** use explicit `.js` extensions, e.g. `import { SearchEngine } from './search-engine.js';` even though the source is `.ts`. TypeScript compiles to ES2022/ESNext.
- `tsconfig.json` has `rootDir: ./src` and excludes `tests/` — the test scripts are intentionally outside the compile tree and import from `dist/`.
- The bundled `mcp.json` in the repo root is a **sample**, not a runtime config — its `args` path points at a developer's machine and there is no `dist/simple-test.js`.
