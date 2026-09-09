# The vector store

Segments are immutable, sealed and content-addressed. The manifest lives in
Basalt and names them.

## Why tombstones

A graph edge removed from a live HNSW strands whatever was reachable only
through it. Deletes are therefore tombstones in the manifest, and a tombstoned
node is still traversed during search because its edges may be the only route to
its neighbours. Compaction is what actually reclaims the space.

## Incremental

Editing one note writes a new segment holding only that note's chunks and
tombstones the old ones. Nothing else is re-embedded.
