# Convergence

Text uses Fugue, which avoids the backward interleaving RGA produces when two
people type at the same anchor in opposite directions.

The file tree uses Kleppmann's move operation. A move that would create a cycle
is ignored, not repaired and not reparented, because both replicas have to reach
the same outcome without asking anyone.
