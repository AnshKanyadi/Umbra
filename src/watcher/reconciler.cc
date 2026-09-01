#include "reconciler.h"

#include <algorithm>
#include <set>
#include <utility>

namespace umbra {
namespace {

// One path's before/after, as the classifier sees it.
struct Delta {
  bool had = false;  // was a vault object here in the snapshot
  bool has = false;  // is a vault object here now
  FileState before;
  FileState after;
  ObjectId old_id;
};

bool VacatedIdentity(const Delta& d) {
  if (!d.had) return false;
  if (!d.has) return true;
  return !d.before.SameInode(d.after);
}

bool ArrivedIdentity(const Delta& d) {
  if (!d.has) return false;
  if (!d.had) return true;
  return !d.before.SameInode(d.after);
}

uint64_t InodeKeyHi(const FileState& s) { return s.dev; }
uint64_t InodeKeyLo(const FileState& s) { return s.ino; }

}  // namespace

Reconciler::Reconciler(Options opts) : opts_(std::move(opts)) {}

bool Reconciler::Lookup(const std::string& rel, ObjectId* id) const {
  const Snapshot::const_iterator it = snap_.find(rel);
  if (it == snap_.end()) return false;
  *id = it->second.id;
  return true;
}

std::size_t Reconciler::Prime() {
  snap_.clear();
  WalkSubtree(
      opts_.abs_root, std::string(),
      [this](const std::string& rel, const FileState& st) {
        if (st.is_dir || rel.empty()) return;
        if (!IsVaultFile(rel)) return;
        FileState full;
        if (ReadFileState(JoinPath(opts_.abs_root, rel),
                          opts_.max_read_attempts, &full) != ReadOutcome::kOk) {
          return;
        }
        Entry e;
        e.st = full;
        e.id = opts_.ids->Next();
        snap_.emplace(rel, e);
      });
  return snap_.size();
}

void Reconciler::ExpandHint(const Hint& h,
                            std::map<std::string, bool>* universe) const {
  const std::string& hint = h.path;
  // The hint itself, whatever it is.
  (*universe)[hint] = (*universe)[hint] || h.renamed;

  // EVERY SNAPSHOT ENTRY AT OR UNDER THE HINT. This is the half that finds a
  // moved or deleted DIRECTORY's children: they are gone from the filesystem,
  // so no walk can find them, and neither backend emits an event for them. The
  // only record that they were ever there is ours.
  //
  // Ordered range from the hint forward; stop at the first key that is not
  // underneath it, which the map's ordering guarantees is the end of the run.
  for (Snapshot::const_iterator it = snap_.lower_bound(hint); it != snap_.end();
       ++it) {
    if (!IsPathAtOrUnder(it->first, hint)) break;
    (*universe)[it->first] = (*universe)[it->first] || h.renamed;
  }

  // And everything that is under the hint NOW, if it is a directory. This is
  // the half that finds a moved directory's children at their new paths.
  FileState st;
  if (StatPath(JoinPath(opts_.abs_root, hint), &st) != ReadOutcome::kOk) return;
  if (!st.is_dir) return;
  const bool renamed = h.renamed;
  WalkSubtree(
      JoinPath(opts_.abs_root, hint), hint,
      [universe, renamed](const std::string& rel, const FileState& child) {
        if (child.is_dir) return;
        (*universe)[rel] = (*universe)[rel] || renamed;
      });
}

std::vector<ChangeEvent> Reconciler::Reconcile(
    const std::vector<Hint>& hints, std::vector<std::string>* retry) {
  // path -> "the platform reported a rename touching this path"
  std::map<std::string, bool> universe;
  for (const Hint& h : hints) ExpandHint(h, &universe);

  // ------------------------------------------------------- look at each path
  std::map<std::string, Delta> deltas;
  for (const std::map<std::string, bool>::value_type& u : universe) {
    const std::string& rel = u.first;
    if (rel.empty()) continue;

    const Snapshot::const_iterator known = snap_.find(rel);
    const bool had = known != snap_.end();

    // A path that is not a vault file cannot be an object. It can still be a
    // directory we walked through, and it can still be an editor temp file that
    // appeared and vanished; neither is reportable.
    if (!IsVaultFile(rel) && !had) continue;

    Delta d;
    d.had = had;
    if (had) {
      d.before = known->second.st;
      d.old_id = known->second.id;
    }

    FileState after;
    const ReadOutcome ro = ReadFileState(JoinPath(opts_.abs_root, rel),
                                         opts_.max_read_attempts, &after);
    switch (ro) {
      case ReadOutcome::kOk:
        // A directory now standing where a file was is not a file. Treat it as
        // absent so the object is deleted rather than hashed as a directory.
        d.has = !after.is_dir && IsVaultFile(rel);
        d.after = after;
        break;
      // ONE ARM FOR TWO OUTCOMES, and they mean the same thing here. kAbsent
      // is a file that was deleted or never existed. kNotRegular is a path that
      // is now a symlink or a device node, which is NOT followed -- following
      // one would let a link out of the vault be read, hashed and eventually
      // synced. From the vault's point of view both are "no object here".
      case ReadOutcome::kAbsent:
      case ReadOutcome::kNotRegular:
        d.has = false;
        break;
      case ReadOutcome::kUnstable:
      case ReadOutcome::kIoError:
        // NO EVENT AND NO SNAPSHOT UPDATE. Emitting from a torn read would
        // publish a hash of bytes that never existed as a version of the file;
        // updating the snapshot without emitting would make the next batch
        // think it had already reported this. Both are worse than waiting.
        retry->push_back(rel);
        continue;
    }

    if (!d.had && !d.has) continue;  // appeared and vanished inside the window
    deltas.emplace(rel, d);
  }

  // ------------------------------------------------ pair moves across paths
  //
  // Ambiguity is refused, not guessed: an inode with more than one arrival or
  // more than one vacancy is a hard link (or a reuse), and inferring a move
  // from it would move the wrong object.
  using InodeKey = std::pair<uint64_t, uint64_t>;
  std::map<InodeKey, std::vector<std::string>> arrivals_by_inode;
  std::map<InodeKey, std::vector<std::string>> vacancies_by_inode;
  for (const std::map<std::string, Delta>::value_type& kv : deltas) {
    const Delta& d = kv.second;
    if (ArrivedIdentity(d)) {
      arrivals_by_inode[InodeKey(InodeKeyHi(d.after), InodeKeyLo(d.after))]
          .push_back(kv.first);
    }
    if (VacatedIdentity(d)) {
      vacancies_by_inode[InodeKey(InodeKeyHi(d.before), InodeKeyLo(d.before))]
          .push_back(kv.first);
    }
  }

  std::vector<ChangeEvent> events;
  std::set<std::string> consumed_arrival;
  std::set<std::string> consumed_vacancy;
  // Paths a move has just written into. A `mv b a` over an existing `a`
  // produces BOTH a delete of the old a and a move into a; the delete must not
  // erase the snapshot row the move just installed.
  std::set<std::string> move_destinations;
  // Applied as one step after every pairing is decided; see the note below.
  std::vector<std::string> move_erases;
  std::vector<std::pair<std::string, Entry>> move_writes;

  for (const std::map<InodeKey, std::vector<std::string>>::value_type& kv :
       arrivals_by_inode) {
    if (kv.second.size() != 1) continue;
    const std::map<InodeKey, std::vector<std::string>>::const_iterator vit =
        vacancies_by_inode.find(kv.first);
    if (vit == vacancies_by_inode.end() || vit->second.size() != 1) continue;

    const std::string& to = kv.second.front();
    const std::string& from = vit->second.front();
    // Same path on both sides is an atomic save, not a move. It is handled
    // below as a modify; consuming it here would emit a move to where the file
    // already is.
    if (to == from) continue;

    const Delta& dst = deltas.find(to)->second;
    const Delta& src = deltas.find(from)->second;

    // HARD LINKS: an inode with more than one name proves nothing by appearing
    // somewhere new, because it never left anywhere. Removing one of two links
    // and creating a third would otherwise read as a move, and the object at
    // the surviving link would silently acquire a second identity. Refused, and
    // the paths fall through to delete and create below -- which is what
    // actually happened.
    if (src.before.nlink > 1 || dst.after.nlink > 1) continue;

    // INODE REUSE: THE PLATFORM MUST HAVE SAID "RENAME".
    //
    // On Linux a file created immediately after another is deleted receives the
    // same inode number AND the same nanosecond mtime -- 198 times out of 200,
    // measured on overlayfs. mtime and size were tried here first and are not
    // sufficient, because that measurement is precisely the case they fail on.
    // Nothing in stat(2) separates the two situations on that platform.
    //
    // The notification does. Both ends of a real rename carry a rename flag
    // from the kernel (inotify) or from FSEvents; a delete followed by a create
    // carries none. Requiring at least ONE of the two paths to have been
    // reported as a rename is what makes the inode pairing trustworthy.
    //
    // ONE and not BOTH: a coalescing backend may deliver the flag on only one
    // end, and losing a move because half the evidence was merged away would be
    // a regression on the common case to defend against a rarer one.
    const bool rename_reported =
        universe.find(to)->second || universe.find(from)->second;
    if (!rename_reported) continue;

    ChangeEvent ev;
    ev.kind = ChangeKind::kMoved;
    ev.id = src.old_id;
    ev.hash = dst.after.hash;
    ev.path = to;
    ev.old_path = from;
    events.push_back(ev);

    // THE SNAPSHOT IS NOT TOUCHED HERE, and that is not tidiness. Two files
    // swapping names produce two moves, a.md -> b.md and b.md -> a.md, and
    // applying each one as it is found makes the second `snap_.erase(from)`
    // delete the row the first had just written. The events were right and the
    // recorded state was left missing an object. So the mutations are collected
    // and applied together below: every erase first, then every write.
    Entry moved;
    moved.st = dst.after;
    moved.id = src.old_id;
    move_erases.push_back(from);
    move_writes.emplace_back(to, moved);

    consumed_arrival.insert(to);
    consumed_vacancy.insert(from);
    move_destinations.insert(to);
  }

  // Every erase, then every write. The order is what makes a swap survive.
  for (const std::string& from : move_erases) snap_.erase(from);
  for (const std::pair<std::string, Entry>& w : move_writes) {
    snap_[w.first] = w.second;
  }

  // ------------------------------------------------------ everything else
  for (const std::map<std::string, Delta>::value_type& kv : deltas) {
    const std::string& rel = kv.first;
    const Delta& d = kv.second;
    const bool arrived_raw = ArrivedIdentity(d);
    const bool vacated_raw = VacatedIdentity(d);
    const bool arrived = arrived_raw && consumed_arrival.count(rel) == 0;
    const bool vacated = vacated_raw && consumed_vacancy.count(rel) == 0;

    if (arrived && vacated) {
      // Both, at one path: the inode under this name was replaced. An atomic
      // save, or a delete-then-create the filesystem cannot distinguish from
      // one. The object survives with its ID.
      if (d.before.hash == d.after.hash) {
        // Rewritten with identical bytes. The object did not change, so there
        // is nothing to sync; refresh the recorded inode and stay quiet.
        Entry e;
        e.st = d.after;
        e.id = d.old_id;
        snap_[rel] = e;
        continue;
      }
      ChangeEvent ev;
      ev.kind = ChangeKind::kModified;
      ev.id = d.old_id;
      ev.hash = d.after.hash;
      ev.path = rel;
      events.push_back(ev);
      Entry e;
      e.st = d.after;
      e.id = d.old_id;
      snap_[rel] = e;
      continue;
    }

    if (arrived) {
      ChangeEvent ev;
      ev.kind = ChangeKind::kCreated;
      ev.id = opts_.ids->Next();
      ev.hash = d.after.hash;
      ev.path = rel;
      events.push_back(ev);
      Entry e;
      e.st = d.after;
      e.id = ev.id;
      snap_[rel] = e;
      continue;
    }

    if (vacated) {
      ChangeEvent ev;
      ev.kind = ChangeKind::kDeleted;
      ev.id = d.old_id;
      ev.hash = ContentHash::Zero();
      ev.path = rel;
      events.push_back(ev);
      // Unless a move has already installed a different object here, which is
      // what `mv b a` over an existing `a` does.
      if (move_destinations.count(rel) == 0) snap_.erase(rel);
      continue;
    }

    // BOTH SIDES WERE CONSUMED BY MOVES. Two files swapping names land here:
    // each path's vacancy went to one move and its arrival came from another,
    // so the moves have said everything there is to say. Falling through to the
    // content comparison below would emit a spurious modify against the object
    // that just left.
    if (arrived_raw || vacated_raw) continue;

    // Same inode on both sides. Only the content can have changed.
    if (d.had && d.has && d.before.hash != d.after.hash) {
      ChangeEvent ev;
      ev.kind = ChangeKind::kModified;
      ev.id = d.old_id;
      ev.hash = d.after.hash;
      ev.path = rel;
      events.push_back(ev);
      Entry e;
      e.st = d.after;
      e.id = d.old_id;
      snap_[rel] = e;
      continue;
    }

    // Touched but unchanged: the mtime moved, the bytes did not. Refresh the
    // recorded stat so the next batch compares against what is really there,
    // and emit nothing. THIS IS THE DEBOUNCE THAT MATTERS -- a hint storm over
    // an unchanged file costs a hash and produces no sync traffic.
    if (d.had && d.has) {
      Entry e;
      e.st = d.after;
      e.id = d.old_id;
      snap_[rel] = e;
    }
  }

  // Deterministic order so the scenario table can assert on the sequence.
  // Sorted by the path the event is ABOUT; a move sorts by its destination.
  std::sort(events.begin(), events.end(),
            [](const ChangeEvent& a, const ChangeEvent& b) {
              if (a.path != b.path) return a.path < b.path;
              return static_cast<int>(a.kind) < static_cast<int>(b.kind);
            });
  return events;
}

}  // namespace umbra
