# Splitting notes into passages

Chunking is deterministic because Phase 5 shares one index between devices. Two
devices that split a note differently produce citations that point at passages
the other does not have, and nothing errors.

## Code blocks

A fenced code block is never split. Half a code block embeds as something that
looks like code and compiles as nothing, and it cites a passage that misleads
whoever follows it.

## Tables

A table that exceeds the ceiling is split at row boundaries and every piece
carries the header row. A table fragment without its header is a grid of values
with no column names.
