# Diagrams

| File | Use |
| --- | --- |
| `architecture.mmd` | Source of truth. Rendered inline in the root [README](../../README.md). |
| `architecture.png` / `.svg` | Exports of the above. PNG for slide decks, SVG for anything that scales. |
| `architecture.drawio` | The same diagram as editable draw.io shapes, for hand-tweaking before a pitch. |
| `architecture-slide.mmd` / `.png` / `.svg` | Tighter variant that stays legible at slide size. |

## Regenerating

```bash
cd docs/diagrams
npx -p @mermaid-js/mermaid-cli mmdc -i architecture.mmd       -o architecture.png       -w 3400 -s 2 -b "#0d0e0f"
npx -p @mermaid-js/mermaid-cli mmdc -i architecture.mmd       -o architecture.svg       -w 3400 -b transparent
npx -p @mermaid-js/mermaid-cli mmdc -i architecture-slide.mmd -o architecture-slide.png -w 2600 -s 2 -b "#0d0e0f"
```

The `.drawio` file is generated rather than hand-authored, so the six columns stay aligned and the
palette stays in step with the Mermaid source — forty-odd `mxCell` blocks edited by hand drift out
of agreement with each other within a couple of revisions.

## Two constraints worth knowing before editing

**Mermaid ignores `direction` inside a subgraph whenever an edge crosses a subgraph boundary.** Both
diagrams therefore connect *cluster to cluster* (`L1 --> L2`) rather than member to member, which is
what lets each column lay out vertically while the overall flow stays horizontal. Wiring a specific
node inside one cluster to a node inside another collapses every column into a single row and the
diagram renders as a 12:1 strip.

**A `%%` comment block at the top of a `.mmd` file breaks the CLI parser** — consecutive comment
lines get concatenated into `%%%%%%flowchart` and the parse fails. Explanatory prose belongs here,
not at the top of the source.

## Colour contract

Both diagrams use one palette, and it carries the argument rather than decorating it:

| Colour | Meaning |
| --- | --- |
| Teal | Deterministic. Same input, same output, no model involved. |
| Purple | The only place a model is consulted, and it can only propose. |
| Amber | A gate. Every model output crosses one before it can affect the run. |
| Red | The isolation boundary. Untrusted code executes only here. |
| Green | Proof-carrying output, and the one component holding a credential. |

Edge labels are dark text on a **light** chip (`edgeLabelBackground: #dfe4e5`). That is deliberate:
which theme variable controls edge-label *text* colour varies between Mermaid versions, so a light
chip is the one choice that stays readable on a dark canvas regardless.
