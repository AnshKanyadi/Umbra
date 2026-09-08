# Project Umbra

A self-hostable sync engine for folders of markdown files.

## Design

The design has three parts. The first is a CRDT for text, which is
what makes two devices editing the same paragraph converge without
anyone arbitrating. The second is a CRDT for the file tree, which is
what makes moving a folder a single fact rather than a delete and a
create. The third is the relay, which stores bytes it cannot read.

### Text

Fugue, because it avoids the backward interleaving that RGA produces
when two people type at the same anchor in opposite directions.

### Tree

Kleppmann's move operation, because a cycle has to be refused rather
than repaired, and both replicas have to refuse it identically.

## Non-goals

- Not a general filesystem sync tool
- Not a collaborative editor with cursors
- Not a hosted service

## Notes

Short section.
