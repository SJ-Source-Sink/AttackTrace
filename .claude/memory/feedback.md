---
name: Feedback & Preferences
description: Patterns Sai has confirmed or corrected — guides how to approach future work
type: feedback
originSessionId: 58800ec8-ee4b-4638-8e58-e37d36bbc2ae
---
## Don't add empty table columns
Don't add a dedicated column to a table if most rows will show "—". Embed the feature inline in an existing cell instead.

**Why:** The Screenshot column showed "—" for all 393 subdomain assets, cluttering the UI. Sai flagged this as "not clean."

**How to apply:** For contextual data (e.g. screenshots only on webapp assets), show it inline in the most relevant existing cell (e.g. Value cell) with an icon/thumbnail that only appears when data exists. Never add a header column that will be empty for the majority of rows.

## Handle broken images gracefully
Always add `onError` to `<img>` tags that load from user-generated or backend-generated paths.

**Why:** Screenshot images may not exist yet (pending scan, capture failed). A broken img icon ruins the UI.

**How to apply:** `onError={(e) => { e.currentTarget.style.display = "none"; }}` on thumbnails. For larger images in modals, hide the img and show a fallback placeholder div.

## Wants proper complete implementations
Sai has explicitly said "Please take time and design and implement it properly." Avoid quick hacks, half-measures, or leaving things wired up to console.log.

**Why:** Platform is being built to enterprise standard. Incomplete implementations erode trust.

**How to apply:** Before shipping a feature, make sure the full loop works — backend endpoint, frontend wiring, error handling, and empty/loading states.

## Use browser automation to verify
Sai uses Claude Code with Chrome browser automation to verify features live. After implementing, check the page in Chrome for console errors and visual issues before declaring done.

**Why:** Catches runtime issues that TypeScript doesn't catch (404s, missing env vars, wrong API shapes).

## Remove raw technical concepts from the UI
Don't expose internal tool concepts (nuclei category tag names, raw CLI flags, etc.) directly in the UI. Translate them to user-friendly labels with descriptions.

**Why:** The original nuclei page had a "Template Categories" card showing raw tags like `cves`, `exposures`, `misconfiguration` as a flat checklist — Sai said "doesn't make sense why it is there."

**How to apply:** Group raw options under a meaningful section. Use a mode selector (All / Categories / Specific) to progressively reveal complexity. Show human labels ("CVEs", "Misconfigurations", "Subdomain Takeovers") with short descriptions alongside each option.

## Show live progress for long-running operations
For scans that take time (nuclei, ffuf), always show a live log/progress panel with stderr output so users know the scan is actually running.

**Why:** Without it, a scan that takes 30s looks identical to one that errored out in 1s — the user has no idea what's happening.

**How to apply:** Forward tool stderr as `progress` SSE events. Render them in a scrollable terminal-style panel (`font-mono`, dark bg) that auto-scrolls. Show the command being run in the panel header.

## Use "Engagement Name" not "Company Name"
Throughout the scan form and any new scan-related UI, the label is "Engagement Name" (not "Company Name"). The DB field is still `company_name`.

**Why:** User renamed it to better reflect pentest/red team use — a scan target is an engagement, not necessarily a company.

**How to apply:** Any new scan form fields, summaries, or labels should say "Engagement Name". Placeholder: "Q2 2026 Pentest".

## Cross-page navigation via URL params (not shared state)
For features that link pages together (e.g. Assets → Takeover), use URL params (`?hosts=a,b,c`) rather than global/shared state.

**Why:** Next.js App Router doesn't have a built-in global store; URL params are simpler, bookmarkable, and work across navigation events.

**How to apply:** Encode selection as comma-joined query param. Destination page reads it both on initial render (for SSR safety) and via `useSearchParams` hook for client-side updates.

## Radix Checkbox requires type="button"
When using `@radix-ui/react-checkbox`, always add `type="button"` to the `CheckboxPrimitive.Root` element.

**Why:** Radix renders the checkbox as a `<button>` — without `type="button"` it defaults to `type="submit"` and submits the parent form when clicked.

**How to apply:** Already fixed in `components/ui/checkbox.tsx`. If adding new Radix interactive elements inside forms, always check the rendered HTML type.
