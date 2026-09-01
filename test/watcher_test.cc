// The vault watcher, exercised against a real filesystem.
//
// TWO LAYERS, AND THE SPLIT IS DELIBERATE.
//
//   1. THE SCENARIO TABLE drives the Reconciler directly. Every row performs
//      REAL filesystem operations in a REAL temp directory -- real inodes, real
//      renames, real timestamps -- and then supplies the hints the platform
//      backend would have supplied. What a row asserts is therefore exactly
//      "this sequence of filesystem operations means these change events", with
//      no dependency on how promptly a kernel notification arrived.
//
//      Driving the table through a live backend instead would make every row
//      also an assertion about notification latency, so a row could fail for a
//      reason unrelated to the behaviour it names -- and it would fail as a
//      timeout, which describes nothing.
//
//   2. THE LIVE BACKEND TESTS ask the platform backend the one question only it
//      can answer: does a real change produce a hint at all. They poll for an
//      expected outcome with a generous deadline rather than sleeping a fixed
//      time and asserting once, because neither FSEvents nor inotify offers any
//      bound on delivery.
//
// Adding a case to the table costs one struct literal.
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "backend_manual.h"
#include "object_id.h"
#include "reconciler.h"
#include "scan.h"
#include "umbra/watcher.h"

namespace umbra {
namespace {

// --------------------------------------------------------------- fixture

// A vault in a temp directory, removed on destruction.
class Vault {
 public:
  Vault() {
    const char* tmp = ::getenv("TMPDIR");
    std::string base = tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp";
    if (!base.empty() && base.back() == '/') base.pop_back();
    std::string tpl = base + "/umbra-watch-test-XXXXXX";
    std::vector<char> buf(tpl.begin(), tpl.end());
    buf.push_back('\0');
    const char* made = ::mkdtemp(buf.data());
    EXPECT_NE(made, nullptr) << "mkdtemp: " << std::strerror(errno);
    if (made == nullptr) return;

    // REALPATH, NOT THE STRING mkdtemp RETURNED. On macOS TMPDIR is under
    // /var/folders and /var is a symlink to /private/var, so the two spellings
    // differ. FSEvents reports the resolved one. A test that kept the
    // unresolved spelling would compare backend paths against a prefix that
    // never matches and would watch a vault whose events all look like they
    // belong to somebody else -- silently.
    std::string resolved;
    EXPECT_EQ(RealPath(made, &resolved), ReadOutcome::kOk);
    root_ = resolved;
  }

  ~Vault() {
    if (root_.empty()) return;
    RemoveTree(root_);
  }

  Vault(const Vault&) = delete;
  Vault& operator=(const Vault&) = delete;

  const std::string& Root() const { return root_; }
  std::string Abs(const std::string& rel) const { return JoinPath(root_, rel); }

  void Mkdir(const std::string& rel) const {
    ASSERT_EQ(::mkdir(Abs(rel).c_str(), 0755), 0)
        << rel << ": " << std::strerror(errno);
  }

  // Truncating write, in place: the inode survives. This is what an editor that
  // writes directly to the file does, and what `echo > f` does.
  void Write(const std::string& rel, const std::string& content) const {
    const int fd = ::open(Abs(rel).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT_GE(fd, 0) << rel << ": " << std::strerror(errno);
    if (!content.empty()) {
      const ssize_t n = ::write(fd, content.data(), content.size());
      EXPECT_EQ(n, static_cast<ssize_t>(content.size()));
    }
    ::close(fd);
  }

  // What most editors actually do: write a temp file next to the target and
  // rename it over. The target's INODE CHANGES. This is the operation that
  // makes inode-as-identity unusable; see reconciler.h.
  void AtomicSave(const std::string& rel, const std::string& content) const {
    const std::string tmp = rel + ".umbra-tmp";
    Write(tmp, content);
    ASSERT_EQ(::rename(Abs(tmp).c_str(), Abs(rel).c_str()), 0)
        << rel << ": " << std::strerror(errno);
  }

  void Rename(const std::string& from, const std::string& to) const {
    ASSERT_EQ(::rename(Abs(from).c_str(), Abs(to).c_str()), 0)
        << from << " -> " << to << ": " << std::strerror(errno);
  }

  void Remove(const std::string& rel) const {
    ASSERT_EQ(::unlink(Abs(rel).c_str()), 0)
        << rel << ": " << std::strerror(errno);
  }

  void Rmdir(const std::string& rel) const {
    ASSERT_EQ(::rmdir(Abs(rel).c_str()), 0)
        << rel << ": " << std::strerror(errno);
  }

  void Symlink(const std::string& target, const std::string& rel) const {
    ASSERT_EQ(::symlink(target.c_str(), Abs(rel).c_str()), 0)
        << rel << ": " << std::strerror(errno);
  }

  void Link(const std::string& from, const std::string& to) const {
    ASSERT_EQ(::link(Abs(from).c_str(), Abs(to).c_str()), 0)
        << from << " => " << to << ": " << std::strerror(errno);
  }

  std::string Read(const std::string& rel) const {
    const int fd = ::open(Abs(rel).c_str(), O_RDONLY);
    if (fd < 0) return std::string();
    std::string out;
    char buf[4096];
    for (;;) {
      const ssize_t n = ::read(fd, buf, sizeof(buf));
      if (n <= 0) break;
      out.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return out;
  }

  static void RemoveTree(const std::string& abs) {
    std::vector<std::string> files;
    std::vector<std::string> dirs;
    WalkSubtree(abs, abs, [&](const std::string& p, const FileState& st) {
      if (st.is_dir) {
        dirs.push_back(p);
      } else {
        files.push_back(p);
      }
    });
    for (const std::string& f : files) ::unlink(f.c_str());
    // Deepest first.
    for (std::vector<std::string>::reverse_iterator it = dirs.rbegin();
         it != dirs.rend(); ++it) {
      ::rmdir(it->c_str());
    }
    ::rmdir(abs.c_str());
  }

 private:
  std::string root_;
};

// ------------------------------------------------------- expectation shape

struct Expect {
  ChangeKind kind = ChangeKind::kCreated;
  std::string path;
  std::string old_path;  // kMoved only

  // The path whose object identity, AS OF BEFORE THE ACT, this event must
  // carry. Empty means "do not check". This is how the table asserts that a
  // move preserves the object and an atomic save does not create a new one --
  // which is the entire point of the design and cannot be checked by looking at
  // kinds alone.
  std::string identity_of;

  // The event's id must match NOTHING that existed before the act.
  bool fresh_identity = false;

  // If set, the event's hash must be the hash of these bytes.
  std::string content;
  bool check_content = false;
};

Expect Created(const std::string& path, const std::string& content) {
  Expect e;
  e.kind = ChangeKind::kCreated;
  e.path = path;
  e.fresh_identity = true;
  e.content = content;
  e.check_content = true;
  return e;
}

Expect Modified(const std::string& path, const std::string& identity_of,
                const std::string& content) {
  Expect e;
  e.kind = ChangeKind::kModified;
  e.path = path;
  e.identity_of = identity_of;
  e.content = content;
  e.check_content = true;
  return e;
}

Expect Deleted(const std::string& path, const std::string& identity_of) {
  Expect e;
  e.kind = ChangeKind::kDeleted;
  e.path = path;
  e.identity_of = identity_of;
  return e;
}

Expect Moved(const std::string& to, const std::string& from,
             const std::string& identity_of, const std::string& content) {
  Expect e;
  e.kind = ChangeKind::kMoved;
  e.path = to;
  e.old_path = from;
  e.identity_of = identity_of;
  e.content = content;
  e.check_content = true;
  return e;
}

// A plain hint, and a hint the platform marked as one end of a rename.
Hint H(const std::string& p) { return Hint(p, false); }
Hint R(const std::string& p) { return Hint(p, true); }

struct Scenario {
  const char* name;
  // Runs BEFORE the reconciler takes its census, so whatever it creates is
  // "what was already there".
  std::function<void(const Vault&)> arrange;
  // The operations under test.
  std::function<void(const Vault&)> act;
  // The hints a backend would have produced for `act`, INCLUDING the rename
  // flag the platform sets -- `R("x")` is a path FSEvents would have marked
  // ItemRenamed and inotify would have reported as IN_MOVED_FROM/IN_MOVED_TO;
  // `H("x")` is a plain notification.
  //
  // Written by hand per row rather than derived: a row that supplied only the
  // vault root would pass for the wrong reason, by making every scenario a full
  // rescan. And the rename flag must be stated rather than inferred, because
  // whether the platform really sets it is the one thing this layer cannot
  // check -- the LiveBackend tests below are what verify that it does.
  std::vector<Hint> hints;
  std::vector<Expect> expect;
};

std::string Describe(const std::vector<ChangeEvent>& evs) {
  std::string s;
  for (const ChangeEvent& e : evs) {
    s += "\n    ";
    s += ChangeKindName(e.kind);
    s += " ";
    s += e.path;
    if (!e.old_path.empty()) {
      s += " (from ";
      s += e.old_path;
      s += ")";
    }
    s += " id=";
    s += e.id.ToHex().substr(0, 8);
  }
  if (s.empty()) s = "\n    (none)";
  return s;
}

// --------------------------------------------------------------- the table

const char kBodyA[] = "# note a\n";
const char kBodyB[] = "# note b\n";
const char kBodyC[] = "# note c, revised\n";

std::vector<Scenario> AllScenarios() {
  std::vector<Scenario> s;

  s.push_back({
      "create_one_file",
      [](const Vault&) {},
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      {H("a.md")},
      {Created("a.md", kBodyA)},
  });

  s.push_back({
      "modify_in_place_keeps_identity",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.Write("a.md", kBodyC); },
      {H("a.md")},
      {Modified("a.md", "a.md", kBodyC)},
  });

  // A write that leaves the bytes identical is not a change. Editors touch
  // files on focus loss; a sync engine that treated every touch as a version
  // would generate traffic for nothing.
  s.push_back({
      "rewrite_identical_bytes_is_not_a_change",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      {H("a.md")},
      {},
  });

  s.push_back({
      "delete_one_file",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.Remove("a.md"); },
      {H("a.md")},
      {Deleted("a.md", "a.md")},
  });

  // THE EDITOR SAVE. Three filesystem operations -- create temp, write temp,
  // rename over -- and the inode under a.md is replaced. One logical change.
  s.push_back({
      "atomic_save_via_temp_and_rename_is_one_modify",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.AtomicSave("a.md", kBodyC); },
      {R("a.md"), R("a.md.umbra-tmp")},
      {Modified("a.md", "a.md", kBodyC)},
  });

  s.push_back({
      "rename_within_a_directory_preserves_identity",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.Rename("a.md", "b.md"); },
      {R("a.md"), R("b.md")},
      {Moved("b.md", "a.md", "a.md", kBodyA)},
  });

  // A RENAME THAT IS REALLY A MOVE. Same syscall, different directory. The
  // reconciler does not distinguish the two cases because at the inode level
  // there is nothing to distinguish.
  s.push_back({
      "move_across_directories_preserves_identity",
      [](const Vault& v) {
        v.Mkdir("src");
        v.Mkdir("dst");
        v.Write("src/a.md", kBodyA);
      },
      [](const Vault& v) { v.Rename("src/a.md", "dst/a.md"); },
      {R("src/a.md"), R("dst/a.md")},
      {Moved("dst/a.md", "src/a.md", "src/a.md", kBodyA)},
  });

  // DELETE THEN CREATE AT THE SAME PATH. Reported as a modify, and that is the
  // documented answer rather than a defect: this is byte-for-byte the same
  // sequence of syscalls an atomic save makes, so no rule can separate them.
  // See the limits section of reconciler.h.
  s.push_back({
      "delete_then_create_same_path_is_a_modify",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Remove("a.md");
        v.Write("a.md", kBodyC);
      },
      {H("a.md")},
      {Modified("a.md", "a.md", kBodyC)},
  });

  // And with the same bytes back, there is nothing to sync at all.
  s.push_back({
      "delete_then_create_same_path_same_bytes_is_silent",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Remove("a.md");
        v.Write("a.md", kBodyA);
      },
      {H("a.md")},
      {},
  });

  // A DIRECTORY MOVED WITH CHILDREN INSIDE IT. Neither platform emits an event
  // for the children: FSEvents reports the directory, inotify reports
  // IN_MOVED_FROM/IN_MOVED_TO on the parent. The children are found by
  // expanding the directory hint over the snapshot AND over the new subtree.
  s.push_back({
      "directory_moved_with_children",
      [](const Vault& v) {
        v.Mkdir("old");
        v.Write("old/a.md", kBodyA);
        v.Write("old/b.md", kBodyB);
      },
      [](const Vault& v) { v.Rename("old", "new"); },
      {R("old"), R("new")},
      {Moved("new/a.md", "old/a.md", "old/a.md", kBodyA),
       Moved("new/b.md", "old/b.md", "old/b.md", kBodyB)},
  });

  s.push_back({
      "nested_directory_moved_preserves_every_descendant",
      [](const Vault& v) {
        v.Mkdir("old");
        v.Mkdir("old/deep");
        v.Write("old/deep/a.md", kBodyA);
      },
      [](const Vault& v) { v.Rename("old", "new"); },
      {R("old"), R("new")},
      {Moved("new/deep/a.md", "old/deep/a.md", "old/deep/a.md", kBodyA)},
  });

  s.push_back({
      "directory_deleted_with_children",
      [](const Vault& v) {
        v.Mkdir("d");
        v.Write("d/a.md", kBodyA);
        v.Write("d/b.md", kBodyB);
      },
      [](const Vault& v) {
        v.Remove("d/a.md");
        v.Remove("d/b.md");
        v.Rmdir("d");
      },
      {H("d")},
      {Deleted("d/a.md", "d/a.md"), Deleted("d/b.md", "d/b.md")},
  });

  // A FILE THAT DISAPPEARS BETWEEN THE EVENT AND THE READ. The hint names a
  // path that is already gone by the time the reconciler looks, and the file
  // was never known. Nothing to report, and nothing to crash on.
  s.push_back({
      "hint_for_a_path_that_never_existed",
      [](const Vault&) {},
      [](const Vault&) {},
      {H("ghost.md"), H("missing/deeper.md")},
      {},
  });

  // Created and removed inside one debounce window. The backend hinted it, but
  // by flush time there is nothing there and there never was anything recorded.
  s.push_back({
      "created_and_deleted_within_one_window",
      [](const Vault&) {},
      [](const Vault& v) {
        v.Write("scratch.md", kBodyA);
        v.Remove("scratch.md");
      },
      {H("scratch.md")},
      {},
  });

  // A known file that vanishes after the hint is a delete, whether or not the
  // read raced it.
  s.push_back({
      "known_file_gone_by_read_time_is_a_delete",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.Remove("a.md"); },
      {H("a.md"), H("a.md")},
      {Deleted("a.md", "a.md")},
  });

  // Moved AND edited before the flush. One event, carrying the NEW content.
  // This row is why the rename evidence is a flag from the platform rather than
  // "the mtime did not change": the edit changes the mtime, and a rule built on
  // mtime would lose the identity here.
  s.push_back({
      "move_and_edit_in_one_window",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Rename("a.md", "b.md");
        v.Write("b.md", kBodyC);
      },
      {R("a.md"), R("b.md")},
      {Moved("b.md", "a.md", "a.md", kBodyC)},
  });

  // A move out of the way followed by a NEW file at the old path. Both facts
  // survive: the object moved, and a different object was created where it was.
  // The move half is a PURE rename (mtime preserved), so it survives the
  // inode-reuse guard; the new file at the old path is a create.
  s.push_back({
      "move_away_then_new_file_at_old_path",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Rename("a.md", "b.md");
        v.Write("a.md", kBodyC);
      },
      {R("a.md"), R("b.md")},
      {Created("a.md", kBodyC), Moved("b.md", "a.md", "a.md", kBodyA)},
  });

  // HARD LINKS MAKE THE INODE EVIDENCE AMBIGUOUS, and ambiguity is refused
  // rather than guessed. Two names share an inode; removing one and adding a
  // third would look like a move if the pairing were done blindly.
  s.push_back({
      "hardlink_ambiguity_is_not_reported_as_a_move",
      [](const Vault& v) {
        v.Write("a.md", kBodyA);
        v.Link("a.md", "b.md");
      },
      [](const Vault& v) {
        v.Remove("a.md");
        v.Link("b.md", "c.md");
      },
      {H("a.md"), H("b.md"), H("c.md")},
      {Deleted("a.md", "a.md"), Created("c.md", kBodyA)},
  });

  // The other half of the hard-link guard: one inode, two NEW names in a batch.
  // Neither can be the destination of a move, because there is nothing to say
  // which one is.
  s.push_back({
      "two_new_hardlinks_to_one_inode_are_not_a_move",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Link("a.md", "c.md");
        v.Link("a.md", "d.md");
        v.Remove("a.md");
      },
      {H("a.md"), H("c.md"), H("d.md")},
      {Deleted("a.md", "a.md"), Created("c.md", kBodyA),
       Created("d.md", kBodyA)},
  });

  // `mv b.md a.md` where a.md already exists. TWO things happened: the object
  // that was at a.md is gone, and the object from b.md is now there. Both are
  // reported, and the move must not be undone by the delete.
  s.push_back({
      "rename_over_an_existing_file_destroys_one_and_moves_the_other",
      [](const Vault& v) {
        v.Write("a.md", kBodyA);
        v.Write("b.md", kBodyB);
      },
      [](const Vault& v) { v.Rename("b.md", "a.md"); },
      {R("a.md"), R("b.md")},
      {Deleted("a.md", "a.md"), Moved("a.md", "b.md", "b.md", kBodyB)},
  });

  s.push_back({
      "non_markdown_files_are_not_vault_objects",
      [](const Vault&) {},
      [](const Vault& v) {
        v.Write("notes.txt", kBodyA);
        v.Write("image.png", kBodyB);
      },
      {H("notes.txt"), H("image.png")},
      {},
  });

  s.push_back({
      "editor_dotfile_temporaries_are_ignored",
      [](const Vault&) {},
      [](const Vault& v) {
        v.Write(".a.md", kBodyA);
        v.Write("#a.md", kBodyB);
      },
      {H(".a.md"), H("#a.md")},
      {},
  });

  // A file replaced by a symlink leaves the vault. It is NOT followed: a
  // symlink to somewhere outside the vault, hashed and synced, is a
  // confidentiality bug rather than a convenience.
  s.push_back({
      "file_replaced_by_symlink_is_a_delete_and_is_not_followed",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Remove("a.md");
        v.Symlink("/etc/hosts", "a.md");
      },
      {H("a.md")},
      {Deleted("a.md", "a.md")},
  });

  // THE OVERFLOW PATH. FSEvents' MustScanSubDirs and inotify's IN_Q_OVERFLOW
  // both reduce to a hint for the vault root, meaning "I lost events, go look".
  // Everything that happened must still be recovered.
  //
  // THIS ROW IS ALSO THE INODE-REUSE REGRESSION TEST, by accident and then on
  // purpose. It deletes d/b.md and creates d/c.md with THE SAME CONTENT in the
  // same batch, and the hint carries no rename flag because a dropped queue has
  // no events left to carry one. On Linux the new file gets the deleted one's
  // inode number AND its mtime, so before the rename flag existed this row
  // reported `moved d/c.md (from d/b.md)` on Linux while passing on macOS. It
  // is left adversarial deliberately: same content, same size, one inode, no
  // rename evidence.
  s.push_back({
      "root_hint_recovers_everything_after_a_dropped_queue",
      [](const Vault& v) {
        v.Mkdir("d");
        v.Write("d/a.md", kBodyA);
        v.Write("d/b.md", kBodyB);
      },
      [](const Vault& v) {
        v.Write("d/a.md", kBodyC);
        v.Remove("d/b.md");
        v.Write("d/c.md", kBodyB);
      },
      {H("")},
      {Modified("d/a.md", "d/a.md", kBodyC), Deleted("d/b.md", "d/b.md"),
       Created("d/c.md", kBodyB)},
  });

  // THE inotify ADD-WATCH RACE, in the shape the reconciler has to survive. A
  // directory appears with children already inside it; on Linux the watch is
  // registered after the fact and the children's creation events were never
  // delivered. The only hint is the directory.
  s.push_back({
      "directory_created_with_children_hinted_only_by_the_directory",
      [](const Vault&) {},
      [](const Vault& v) {
        v.Mkdir("fresh");
        v.Write("fresh/a.md", kBodyA);
        v.Write("fresh/b.md", kBodyB);
      },
      {H("fresh")},
      {Created("fresh/a.md", kBodyA), Created("fresh/b.md", kBodyB)},
  });

  // A file moved in from outside the vault has an arrival with no matching
  // vacancy, so it is a create -- correctly, since the object was never ours.
  s.push_back({
      "file_moved_in_from_outside_the_vault_is_a_create",
      [](const Vault& v) { v.Mkdir("sub"); },
      [](const Vault& v) {
        // "Outside" is modelled by a name the vault does not consider an
        // object; it becomes one only on arrival.
        v.Write("staging.txt", kBodyB);
        v.Rename("staging.txt", "sub/arrived.md");
      },
      {R("staging.txt"), R("sub/arrived.md")},
      {Created("sub/arrived.md", kBodyB)},
  });

  s.push_back({
      "file_moved_out_of_the_vault_is_a_delete",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) { v.Rename("a.md", "gone.txt"); },
      {R("a.md"), R("gone.txt")},
      {Deleted("a.md", "a.md")},
  });

  s.push_back({
      "empty_file_is_a_real_object",
      [](const Vault&) {},
      [](const Vault& v) { v.Write("empty.md", ""); },
      {H("empty.md")},
      {Created("empty.md", "")},
  });

  s.push_back({
      "two_independent_files_in_one_batch",
      [](const Vault& v) { v.Write("a.md", kBodyA); },
      [](const Vault& v) {
        v.Write("a.md", kBodyC);
        v.Write("b.md", kBodyB);
      },
      {H("a.md"), H("b.md")},
      {Modified("a.md", "a.md", kBodyC), Created("b.md", kBodyB)},
  });

  // Two files swapping names in one window. Both moves must be found, and
  // neither may steal the other's identity.
  s.push_back({
      "two_files_swap_paths",
      [](const Vault& v) {
        v.Write("a.md", kBodyA);
        v.Write("b.md", kBodyB);
      },
      [](const Vault& v) {
        v.Rename("a.md", "tmp.md");
        v.Rename("b.md", "a.md");
        v.Rename("tmp.md", "b.md");
      },
      {R("a.md"), R("b.md"), R("tmp.md")},
      {Moved("a.md", "b.md", "b.md", kBodyB),
       Moved("b.md", "a.md", "a.md", kBodyA)},
  });

  return s;
}

// ---------------------------------------------------------- the table runner

class ScenarioTest : public ::testing::TestWithParam<std::size_t> {};

TEST_P(ScenarioTest, Behaves) {
  // Held by value: AllScenarios() returns a fresh vector, and binding a
  // reference into a temporary would dangle. -Wdangling-gsl caught this.
  const std::vector<Scenario> all = AllScenarios();
  const Scenario& sc = all[GetParam()];
  Vault v;
  ASSERT_FALSE(v.Root().empty());

  sc.arrange(v);
  if (::testing::Test::HasFatalFailure()) return;

  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);
  Reconciler::Options ropts;
  ropts.abs_root = v.Root();
  ropts.ids = ids.get();
  Reconciler rec(ropts);
  rec.Prime();

  // Identities as they stood before the act, so the expectations can say "this
  // must still be that object".
  std::map<std::string, ObjectId> before_ids;
  std::set<std::string> before_id_hexes;
  for (const Expect& e : sc.expect) {
    if (e.identity_of.empty()) continue;
    ObjectId id;
    ASSERT_TRUE(rec.Lookup(e.identity_of, &id))
        << "scenario " << sc.name << " expects an identity for '"
        << e.identity_of << "' but nothing was primed at that path";
    before_ids[e.identity_of] = id;
  }
  {
    // Every identity that exists before the act, for the fresh_identity check.
    std::vector<std::string> all;
    WalkSubtree(v.Root(), std::string(),
                [&all](const std::string& rel, const FileState& st) {
                  if (!st.is_dir && !rel.empty()) all.push_back(rel);
                });
    for (const std::string& p : all) {
      ObjectId id;
      if (rec.Lookup(p, &id)) before_id_hexes.insert(id.ToHex());
    }
  }

  sc.act(v);
  if (::testing::Test::HasFatalFailure()) return;

  std::vector<std::string> retry;
  const std::vector<ChangeEvent> got = rec.Reconcile(sc.hints, &retry);

  EXPECT_TRUE(retry.empty())
      << "scenario " << sc.name << " left paths needing a retry; the table is "
      << "not supposed to race a writer";

  ASSERT_EQ(got.size(), sc.expect.size())
      << "scenario " << sc.name << " produced:" << Describe(got);

  for (std::size_t i = 0; i < sc.expect.size(); ++i) {
    const Expect& want = sc.expect[i];
    const ChangeEvent& ev = got[i];
    EXPECT_EQ(ev.kind, want.kind) << sc.name << " event " << i << Describe(got);
    EXPECT_EQ(ev.path, want.path) << sc.name << " event " << i << Describe(got);
    EXPECT_EQ(ev.old_path, want.old_path)
        << sc.name << " event " << i << Describe(got);

    if (!want.identity_of.empty()) {
      EXPECT_EQ(ev.id, before_ids[want.identity_of])
          << sc.name << " event " << i << ": identity of '" << want.identity_of
          << "' was not preserved" << Describe(got);
    }
    if (want.fresh_identity) {
      EXPECT_EQ(before_id_hexes.count(ev.id.ToHex()), 0u)
          << sc.name << " event " << i << ": expected a NEW object identity"
          << Describe(got);
    }
    if (want.check_content) {
      EXPECT_EQ(ev.hash, HashBytes(want.content.data(), want.content.size()))
          << sc.name << " event " << i << ": content hash mismatch"
          << Describe(got);
    }
    if (ev.kind == ChangeKind::kDeleted) {
      EXPECT_TRUE(ev.hash.IsZero()) << sc.name << ": a delete carries no hash";
    }
  }
}

std::string ScenarioName(const ::testing::TestParamInfo<std::size_t>& info) {
  return AllScenarios()[info.param].name;
}

INSTANTIATE_TEST_SUITE_P(Table, ScenarioTest,
                         ::testing::Range(std::size_t{0},
                                          AllScenarios().size()),
                         ScenarioName);

// ------------------------------------------------- modified while being read

// A FILE REPLACED CONTINUOUSLY WHILE THE RECONCILER READS IT.
//
// The writer uses the write-temp-and-rename pattern, so the watched path only
// ever names a COMPLETE version -- a reader that opens it gets one whole
// version or another, never a mixture, because rename does not disturb an
// already-open descriptor. That makes the assertion exact: every hash the
// reconciler reports must be the hash of one of the versions the writer wrote.
// A hash outside that set would mean the event stream carried content that was
// never on disk.
TEST(TornRead, AtomicReplacementNeverReportsAHashThatWasNeverOnDisk) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());

  std::vector<std::string> versions;
  versions.reserve(4);
  for (int i = 0; i < 4; ++i) {
    // Distinct lengths as well as distinct bytes, so a hash collision cannot
    // launder a wrong answer into a right-looking one.
    versions.emplace_back(64 * 1024 + static_cast<std::size_t>(i) * 1024,
                          static_cast<char>('a' + i));
  }
  std::set<std::string> allowed;
  for (const std::string& body : versions) {
    allowed.insert(HashBytes(body.data(), body.size()).ToHex());
  }

  v.Write("busy.md", versions[0]);

  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);
  Reconciler::Options ropts;
  ropts.abs_root = v.Root();
  ropts.ids = ids.get();
  Reconciler rec(ropts);
  rec.Prime();

  std::atomic<bool> stop(false);
  std::atomic<int> writes(0);
  std::thread writer([&] {
    int i = 1;
    while (!stop.load()) {
      const std::string& body =
          versions[static_cast<std::size_t>(i) % versions.size()];
      const std::string tmp = v.Abs("busy.md.wtmp");
      const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) {
        ssize_t n = ::write(fd, body.data(), body.size());
        (void)n;
        ::close(fd);
        if (::rename(tmp.c_str(), v.Abs("busy.md").c_str()) == 0) {
          writes.fetch_add(1);
        }
      }
      ++i;
      // A PAUSE, AND IT IS LOAD-BEARING RATHER THAN POLITE. Every rename
      // changes the inode under busy.md, and a read that spans one is correctly
      // rejected as inconsistent. With no pause at all -- and especially under
      // a sanitizer, where the read is several times slower -- EVERY attempt
      // loses that race, the reconciler correctly reports nothing, and the test
      // would be asserting against a scheduler rather than against behaviour.
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  });

  int reported = 0;
  for (int round = 0; round < 60; ++round) {
    std::vector<std::string> retry;
    const std::vector<ChangeEvent> evs =
        rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry);
    for (const ChangeEvent& e : evs) {
      ++reported;
      EXPECT_EQ(allowed.count(e.hash.ToHex()), 1u)
          << "reported a content hash that no version of the file ever had";
      EXPECT_EQ(e.kind, ChangeKind::kModified)
          << "replacing a file in place is a modify, not a create";
    }
  }

  stop.store(true);
  writer.join();
  EXPECT_GT(writes.load(), 0)
      << "the writer never ran; the race was not set up";

  // AND IT SETTLES. How many events landed during the churn depends on who won
  // which race and is not asserted -- under a sanitizer the reader may lose
  // every one of them, which is the correct outcome and not a failure. What is
  // asserted is that once the writing stops, the reconciler agrees with the
  // disk: one pass to settle, a second that finds nothing left to say.
  std::vector<std::string> retry;
  rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry);
  EXPECT_TRUE(retry.empty()) << "a quiescent file was still unreadable";
  std::vector<std::string> retry2;
  const std::vector<ChangeEvent> settled =
      rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry2);
  EXPECT_TRUE(settled.empty())
      << "a quiescent file still produced events" << Describe(settled);
  EXPECT_EQ(allowed.count(
                HashBytes(v.Read("busy.md").data(), v.Read("busy.md").size())
                    .ToHex()),
            1u)
      << "the file on disk is not any version the writer wrote";
  (void)reported;
}

// AN IN-PLACE REWRITE IS A DIFFERENT PROBLEM, AND THE DIFFERENCE IS WORTH A
// TEST OF ITS OWN.
//
// `open(O_TRUNC)` followed by `write()` puts the file through states that are
// NOT any complete version: it is genuinely zero bytes for an instant, and
// genuinely a prefix for longer. Those are real states of the file, not torn
// reads -- a reader that observes one has observed something true.
//
// So the assertion here is not "every hash is a known version". It is the two
// things that actually hold: reads never report and retry the same path in one
// batch, and the reconciler CONVERGES on the final content once the writing
// stops. Convergence is the property the sync engine depends on; a transient
// report of a half-written file is corrected by the next batch.
TEST(TornRead, InPlaceRewriteConvergesOnTheFinalContent) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());

  std::vector<std::string> versions;
  versions.reserve(4);
  for (int i = 0; i < 4; ++i) {
    versions.emplace_back(256 * 1024 + static_cast<std::size_t>(i) * 4096,
                          static_cast<char>('a' + i));
  }
  v.Write("busy.md", versions[0]);

  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);
  Reconciler::Options ropts;
  ropts.abs_root = v.Root();
  ropts.ids = ids.get();
  Reconciler rec(ropts);
  rec.Prime();

  std::atomic<bool> stop(false);
  std::thread writer([&] {
    int i = 1;
    while (!stop.load()) {
      const std::string& body =
          versions[static_cast<std::size_t>(i) % versions.size()];
      const int fd = ::open(v.Abs("busy.md").c_str(), O_WRONLY | O_TRUNC);
      if (fd >= 0) {
        ssize_t n = ::write(fd, body.data(), body.size());
        (void)n;
        ::close(fd);
      }
      ++i;
    }
  });

  for (int round = 0; round < 60; ++round) {
    std::vector<std::string> retry;
    const std::vector<ChangeEvent> evs =
        rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry);
    if (!retry.empty()) {
      EXPECT_TRUE(evs.empty())
          << "a path was both reported and queued for retry in one batch";
    }
  }

  stop.store(true);
  writer.join();

  // Quiescent. One pass to settle on whatever is there, then a second that must
  // find nothing left to say -- and the settled hash must be the real content.
  const std::string final_bytes = v.Read("busy.md");
  std::vector<std::string> retry;
  rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry);
  EXPECT_TRUE(retry.empty()) << "a quiescent file was still unreadable";

  std::vector<std::string> retry2;
  const std::vector<ChangeEvent> settled =
      rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry2);
  EXPECT_TRUE(settled.empty())
      << "a quiescent file still produced events" << Describe(settled);

  ObjectId id;
  ASSERT_TRUE(rec.Lookup("busy.md", &id));
  // The reconciler's recorded state must agree with the bytes on disk.
  std::vector<std::string> retry3;
  v.Write("busy.md", final_bytes + "\n");
  const std::vector<ChangeEvent> after =
      rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry3);
  ASSERT_EQ(after.size(), 1u) << Describe(after);
  EXPECT_EQ(after[0].kind, ChangeKind::kModified);
  EXPECT_EQ(after[0].id, id) << "identity was lost across the churn";
}

// The retry contract itself: a path handed back for retry must never also have
// produced an event in the same batch. One attempt makes an interrupted read
// give up immediately, which is what puts the path on the retry list at all.
TEST(TornRead, UnstablePathsAreRetriedRatherThanReported) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  const std::string body(1024 * 1024, 'x');
  v.Write("busy.md", body);

  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);
  Reconciler::Options ropts;
  ropts.abs_root = v.Root();
  ropts.ids = ids.get();
  ropts.max_read_attempts = 1;
  Reconciler rec(ropts);
  rec.Prime();

  std::atomic<bool> stop(false);
  std::thread writer([&] {
    char c = 'a';
    while (!stop.load()) {
      const int fd = ::open(v.Abs("busy.md").c_str(), O_WRONLY | O_TRUNC);
      if (fd >= 0) {
        const std::string b(1024 * 1024, c);
        ssize_t n = ::write(fd, b.data(), b.size());
        (void)n;
        ::close(fd);
      }
      c = c == 'z' ? 'a' : static_cast<char>(c + 1);
    }
  });

  for (int round = 0; round < 60; ++round) {
    std::vector<std::string> retry;
    const std::vector<ChangeEvent> evs =
        rec.Reconcile(std::vector<Hint>{H("busy.md")}, &retry);
    if (!retry.empty()) {
      EXPECT_TRUE(evs.empty())
          << "a path was both reported and queued for retry in one batch";
    }
  }
  stop.store(true);
  writer.join();
}

// THE SNAPSHOT AFTER A SWAP, WHICH THE EVENT ASSERTIONS DO NOT COVER.
//
// The table checks what a batch EMITS. It does not check what the reconciler
// then believes, and those came apart: two files swapping names emitted two
// correct moves while the second move's `erase(from)` deleted the row the first
// had just written, leaving one object missing from the snapshot entirely. The
// next batch would then have reported the surviving file as a create.
//
// So this asserts the recorded state directly, and then asserts the thing that
// state exists for: that the following batch is quiet.
TEST(Reconcile, SwappingTwoPathsLeavesBothObjectsRecorded) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Write("a.md", kBodyA);
  v.Write("b.md", kBodyB);

  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);
  Reconciler::Options ropts;
  ropts.abs_root = v.Root();
  ropts.ids = ids.get();
  Reconciler rec(ropts);
  ASSERT_EQ(rec.Prime(), 2u);

  ObjectId id_a;
  ObjectId id_b;
  ASSERT_TRUE(rec.Lookup("a.md", &id_a));
  ASSERT_TRUE(rec.Lookup("b.md", &id_b));
  ASSERT_NE(id_a, id_b);

  v.Rename("a.md", "tmp.md");
  v.Rename("b.md", "a.md");
  v.Rename("tmp.md", "b.md");

  std::vector<std::string> retry;
  const std::vector<ChangeEvent> evs = rec.Reconcile(
      std::vector<Hint>{R("a.md"), R("b.md"), R("tmp.md")}, &retry);
  ASSERT_EQ(evs.size(), 2u) << Describe(evs);

  // BOTH objects are still known, and they have traded places.
  EXPECT_EQ(rec.Size(), 2u) << "an object fell out of the snapshot";
  ObjectId now_a;
  ObjectId now_b;
  ASSERT_TRUE(rec.Lookup("a.md", &now_a)) << "a.md is no longer recorded";
  ASSERT_TRUE(rec.Lookup("b.md", &now_b)) << "b.md is no longer recorded";
  EXPECT_EQ(now_a, id_b) << "a.md should now hold what b.md was";
  EXPECT_EQ(now_b, id_a) << "b.md should now hold what a.md was";

  // And the state is consistent with the disk: a full rescan finds nothing new.
  std::vector<std::string> retry2;
  const std::vector<ChangeEvent> settled =
      rec.Reconcile(std::vector<Hint>{H("")}, &retry2);
  EXPECT_TRUE(settled.empty())
      << "the batch after a swap invented changes" << Describe(settled);
}

// ------------------------------------------------------------- prime / adopt

TEST(Prime, AdoptsAnExistingVaultWithoutReportingIt) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Mkdir("d");
  v.Write("a.md", kBodyA);
  v.Write("d/b.md", kBodyB);
  v.Write("d/notes.txt", kBodyA);

  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);
  Reconciler::Options ropts;
  ropts.abs_root = v.Root();
  ropts.ids = ids.get();
  Reconciler rec(ropts);
  EXPECT_EQ(rec.Prime(), 2u) << "only the .md files are vault objects";

  std::vector<std::string> retry;
  const std::vector<ChangeEvent> evs =
      rec.Reconcile(std::vector<Hint>{H("")}, &retry);
  EXPECT_TRUE(evs.empty()) << "priming then rescanning invented changes"
                           << Describe(evs);
}

// ------------------------------------------------------------ path helpers

TEST(PathHelpers, ContainmentRequiresASeparator) {
  EXPECT_TRUE(IsPathAtOrUnder("notes/a.md", "notes"));
  EXPECT_TRUE(IsPathAtOrUnder("notes", "notes"));
  EXPECT_TRUE(IsPathAtOrUnder("anything", ""));
  // The case a naive prefix test gets wrong.
  EXPECT_FALSE(IsPathAtOrUnder("notes-archive/a.md", "notes"));
  EXPECT_FALSE(IsPathAtOrUnder("note", "notes"));
}

TEST(PathHelpers, VaultFileRecognition) {
  EXPECT_TRUE(IsVaultFile("a.md"));
  EXPECT_TRUE(IsVaultFile("d/a.MD"));
  EXPECT_FALSE(IsVaultFile("a.txt"));
  EXPECT_FALSE(IsVaultFile("a"));
  EXPECT_FALSE(IsVaultFile(".a.md"));
  EXPECT_FALSE(IsVaultFile("d/#a.md"));
  EXPECT_FALSE(IsVaultFile("a.md.swp"));
}

// KNOWN-ANSWER TESTS, because "it is a hash" and "it is the hash we said it is"
// are different claims. These digests were not produced by the code under test:
// they are BLAKE2b-256 of the empty string and of "abc", which any independent
// implementation agrees on. A build that silently linked a different hash, or
// libsodium configured for a different digest length, fails here rather than
// producing self-consistent garbage that every replica agrees on.
TEST(ContentHashing, MatchesPublishedBlake2b256Vectors) {
  EXPECT_EQ(HashBytes("", 0).ToHex(),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
  const std::string abc = "abc";
  EXPECT_EQ(HashBytes(abc.data(), abc.size()).ToHex(),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
}

TEST(ContentHashing, DistinguishesLengthAndBytes) {
  const std::string a = "hello";
  const std::string b = "hello ";
  EXPECT_NE(HashBytes(a.data(), a.size()), HashBytes(b.data(), b.size()));
  EXPECT_EQ(HashBytes(a.data(), a.size()), HashBytes(a.data(), a.size()));
  // An empty file has a real digest, distinguishable from the "no content"
  // sentinel a delete carries.
  EXPECT_FALSE(HashBytes("", 0).IsZero());
  EXPECT_TRUE(ContentHash::Zero().IsZero());
}

// -------------------------------------------------------- watcher plumbing

// Collects change batches from the watcher's thread.
class Collector {
 public:
  void Add(const std::vector<ChangeEvent>& evs) {
    std::lock_guard<std::mutex> lock(mu_);
    ++batches_;
    for (const ChangeEvent& e : evs) events_.push_back(e);
  }

  std::vector<ChangeEvent> Events() const {
    std::lock_guard<std::mutex> lock(mu_);
    return events_;
  }

  int Batches() const {
    std::lock_guard<std::mutex> lock(mu_);
    return batches_;
  }

  // Polls rather than sleeping once: neither platform bounds notification
  // delivery, so the only honest wait is "until it happens, or a deadline".
  bool WaitForEvents(std::size_t n, std::chrono::milliseconds timeout) const {
    const std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + timeout;
    for (;;) {
      {
        std::lock_guard<std::mutex> lock(mu_);
        if (events_.size() >= n) return true;
      }
      if (std::chrono::steady_clock::now() >= deadline) return false;
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

 private:
  mutable std::mutex mu_;
  std::vector<ChangeEvent> events_;
  int batches_ = 0;
};

TEST(Watcher, RefusesARootThatIsNotADirectory) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Write("a.md", kBodyA);

  WatcherOptions opts;
  opts.root = v.Abs("a.md");
  std::unique_ptr<VaultWatcher> w;
  EXPECT_EQ(VaultWatcher::Open(opts, &w), WatchStatus::kRootNotDirectory);

  opts.root = v.Abs("nope");
  EXPECT_EQ(VaultWatcher::Open(opts, &w), WatchStatus::kRootNotFound);
}

TEST(Watcher, DebounceCollapsesAHintBurstIntoOneBatch) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());

  ManualBackend backend;
  Collector sink;
  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);

  WatcherOptions opts;
  opts.root = v.Root();
  opts.backend = &backend;
  opts.ids = ids.get();
  opts.quiet_period = std::chrono::milliseconds(40);
  opts.max_delay = std::chrono::milliseconds(2000);
  opts.on_change = [&sink](const std::vector<ChangeEvent>& e) { sink.Add(e); };

  std::unique_ptr<VaultWatcher> w;
  ASSERT_EQ(VaultWatcher::Open(opts, &w), WatchStatus::kOk);
  EXPECT_STREQ(w->BackendName(), "manual");

  // One save, three hints, as an editor produces.
  v.AtomicSave("a.md", kBodyA);
  backend.Emit("a.md.umbra-tmp");
  backend.Emit("a.md.umbra-tmp");
  backend.Emit("a.md");

  ASSERT_TRUE(sink.WaitForEvents(1, std::chrono::seconds(5)));
  ASSERT_TRUE(w->WaitForIdle(std::chrono::seconds(5)));
  w->Stop();

  const std::vector<ChangeEvent> evs = sink.Events();
  ASSERT_EQ(evs.size(), 1u) << Describe(evs);
  EXPECT_EQ(evs[0].kind, ChangeKind::kCreated);
  EXPECT_EQ(evs[0].path, "a.md");
  EXPECT_EQ(sink.Batches(), 1) << "one save produced more than one batch";
}

TEST(Watcher, MaxDelayForcesAFlushUnderAContinuousHintStream) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());

  ManualBackend backend;
  Collector sink;
  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);

  WatcherOptions opts;
  opts.root = v.Root();
  opts.backend = &backend;
  opts.ids = ids.get();
  // A quiet period that a continuous stream of hints would never satisfy, and a
  // short cap. Without the cap this test would hang, which is the point of it.
  opts.quiet_period = std::chrono::milliseconds(10000);
  opts.max_delay = std::chrono::milliseconds(150);
  opts.on_change = [&sink](const std::vector<ChangeEvent>& e) { sink.Add(e); };

  std::unique_ptr<VaultWatcher> w;
  ASSERT_EQ(VaultWatcher::Open(opts, &w), WatchStatus::kOk);

  v.Write("a.md", kBodyA);
  std::atomic<bool> stop(false);
  std::thread noisy([&] {
    while (!stop.load()) {
      backend.Emit("a.md");
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  });

  const bool arrived = sink.WaitForEvents(1, std::chrono::seconds(10));
  stop.store(true);
  noisy.join();
  w->Stop();
  EXPECT_TRUE(arrived)
      << "the debounce starved: quiet_period never elapsed and "
      << "max_delay did not force a flush";
}

TEST(Watcher, AdoptsAnExistingVaultSilently) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Write("a.md", kBodyA);
  v.Write("b.md", kBodyB);

  ManualBackend backend;
  Collector sink;
  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);

  WatcherOptions opts;
  opts.root = v.Root();
  opts.backend = &backend;
  opts.ids = ids.get();
  opts.on_change = [&sink](const std::vector<ChangeEvent>& e) { sink.Add(e); };

  std::unique_ptr<VaultWatcher> w;
  ASSERT_EQ(VaultWatcher::Open(opts, &w), WatchStatus::kOk);
  EXPECT_EQ(w->ObjectCount(), 2u);

  backend.Emit("");
  ASSERT_TRUE(w->WaitForIdle(std::chrono::seconds(5)));
  w->Stop();
  EXPECT_EQ(sink.Batches(), 0)
      << "opening a vault reported its contents as new";
}

TEST(Watcher, StopIsIdempotentAndSilencesTheBackend) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());

  ManualBackend backend;
  Collector sink;
  std::unique_ptr<ObjectIdSource> ids = MakeSequentialObjectIdSource(1);

  WatcherOptions opts;
  opts.root = v.Root();
  opts.backend = &backend;
  opts.ids = ids.get();
  opts.on_change = [&sink](const std::vector<ChangeEvent>& e) { sink.Add(e); };

  std::unique_ptr<VaultWatcher> w;
  ASSERT_EQ(VaultWatcher::Open(opts, &w), WatchStatus::kOk);
  w->Stop();
  w->Stop();

  // Emitting after Stop must reach nothing. Under ASan and TSan this is also
  // the assertion that Stop's ordering does not leave the sink pointing at
  // destroyed state.
  v.Write("a.md", kBodyA);
  backend.Emit("a.md");
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  EXPECT_EQ(sink.Batches(), 0);
}

// ------------------------------------------------------ the real backend

// THESE ARE THE ONLY TESTS THAT ASK THE PLATFORM API ANYTHING. Everything above
// asserts what a set of filesystem operations MEANS; these assert that the
// operating system tells us about them at all.
class LiveBackend : public ::testing::Test {
 protected:
  void OpenWatcher(Vault* v) {
    ids_ = MakeSequentialObjectIdSource(1);
    WatcherOptions opts;
    opts.root = v->Root();
    opts.ids = ids_.get();
    opts.quiet_period = std::chrono::milliseconds(60);
    opts.max_delay = std::chrono::milliseconds(500);
    opts.on_change = [this](const std::vector<ChangeEvent>& e) {
      sink_.Add(e);
    };
    ASSERT_EQ(VaultWatcher::Open(opts, &w_), WatchStatus::kOk);
  }

  // Long, and deliberately so. FSEvents and inotify give no delivery bound, and
  // a sanitizer lane makes everything slower. A generous deadline that is
  // polled costs nothing when the event arrives promptly.
  static std::chrono::milliseconds Deadline() {
    return std::chrono::seconds(20);
  }

  std::unique_ptr<ObjectIdSource> ids_;
  std::unique_ptr<VaultWatcher> w_;
  Collector sink_;
};

TEST_F(LiveBackend, NamesItself) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  OpenWatcher(&v);
  const std::string name = w_->BackendName();
  w_->Stop();
#if defined(__APPLE__)
  EXPECT_EQ(name, "fsevents");
#elif defined(__linux__)
  EXPECT_EQ(name, "inotify");
#else
  FAIL() << "no backend is expected on this platform";
#endif
}

TEST_F(LiveBackend, ReportsACreate) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  OpenWatcher(&v);
  v.Write("a.md", kBodyA);

  ASSERT_TRUE(sink_.WaitForEvents(1, Deadline()))
      << "the platform backend delivered no hint for a new file";
  const std::vector<ChangeEvent> evs = sink_.Events();
  w_->Stop();
  ASSERT_GE(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, ChangeKind::kCreated) << Describe(evs);
  EXPECT_EQ(evs[0].path, "a.md") << Describe(evs);
}

TEST_F(LiveBackend, ReportsAnAtomicSaveAsOneModify) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Write("a.md", kBodyA);
  OpenWatcher(&v);

  v.AtomicSave("a.md", kBodyC);
  ASSERT_TRUE(sink_.WaitForEvents(1, Deadline()));
  ASSERT_TRUE(w_->WaitForIdle(Deadline()));
  const std::vector<ChangeEvent> evs = sink_.Events();
  w_->Stop();

  ASSERT_EQ(evs.size(), 1u)
      << "an editor-style save did not collapse to one change" << Describe(evs);
  EXPECT_EQ(evs[0].kind, ChangeKind::kModified) << Describe(evs);
  EXPECT_EQ(evs[0].path, "a.md");
  EXPECT_EQ(evs[0].hash, HashBytes(kBodyC, std::strlen(kBodyC)));
}

TEST_F(LiveBackend, ReportsAMoveAcrossDirectories) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Mkdir("src");
  v.Mkdir("dst");
  v.Write("src/a.md", kBodyA);
  OpenWatcher(&v);

  ObjectId before;
  v.Rename("src/a.md", "dst/a.md");
  ASSERT_TRUE(sink_.WaitForEvents(1, Deadline()));
  ASSERT_TRUE(w_->WaitForIdle(Deadline()));
  const std::vector<ChangeEvent> evs = sink_.Events();
  w_->Stop();
  (void)before;

  ASSERT_EQ(evs.size(), 1u) << Describe(evs);
  EXPECT_EQ(evs[0].kind, ChangeKind::kMoved) << Describe(evs);
  EXPECT_EQ(evs[0].path, "dst/a.md");
  EXPECT_EQ(evs[0].old_path, "src/a.md");
}

TEST_F(LiveBackend, ReportsADelete) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Write("a.md", kBodyA);
  OpenWatcher(&v);

  v.Remove("a.md");
  ASSERT_TRUE(sink_.WaitForEvents(1, Deadline()));
  const std::vector<ChangeEvent> evs = sink_.Events();
  w_->Stop();
  ASSERT_EQ(evs.size(), 1u) << Describe(evs);
  EXPECT_EQ(evs[0].kind, ChangeKind::kDeleted) << Describe(evs);
  EXPECT_EQ(evs[0].path, "a.md");
}

// A DIRECTORY CREATED WITH CHILDREN, THROUGH THE REAL BACKEND. This is the
// inotify add-watch race in its live form: on Linux the watch on `fresh` is
// registered after the directory exists, and the children may be created before
// that happens. The hint-and-rescan design is what makes this pass.
TEST_F(LiveBackend, FindsChildrenOfADirectoryCreatedAllAtOnce) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  OpenWatcher(&v);

  v.Mkdir("fresh");
  v.Write("fresh/a.md", kBodyA);
  v.Write("fresh/b.md", kBodyB);

  ASSERT_TRUE(sink_.WaitForEvents(2, Deadline()))
      << "children of a newly created directory were not reported";
  ASSERT_TRUE(w_->WaitForIdle(Deadline()));
  std::vector<ChangeEvent> evs = sink_.Events();
  w_->Stop();

  std::set<std::string> paths;
  for (const ChangeEvent& e : evs) {
    EXPECT_EQ(e.kind, ChangeKind::kCreated) << Describe(evs);
    paths.insert(e.path);
  }
  EXPECT_EQ(paths.count("fresh/a.md"), 1u) << Describe(evs);
  EXPECT_EQ(paths.count("fresh/b.md"), 1u) << Describe(evs);
}

TEST_F(LiveBackend, ReportsAMovedDirectorysChildren) {
  Vault v;
  ASSERT_FALSE(v.Root().empty());
  v.Mkdir("old");
  v.Write("old/a.md", kBodyA);
  v.Write("old/b.md", kBodyB);
  OpenWatcher(&v);

  v.Rename("old", "new");
  ASSERT_TRUE(sink_.WaitForEvents(2, Deadline()))
      << "a moved directory's children were not reported";
  ASSERT_TRUE(w_->WaitForIdle(Deadline()));
  const std::vector<ChangeEvent> evs = sink_.Events();
  w_->Stop();

  // THE KIND IS ASSERTED, NOT ONLY THE PATH. An earlier version of this test
  // checked the reported paths alone and stayed green when the FSEvents rename
  // flag was forced off -- the children were reported as CREATES at the new
  // paths, which satisfies a path-only assertion while losing every object's
  // identity. Asserting the kind is what makes this test cover the thing it is
  // named for.
  std::map<std::string, const ChangeEvent*> by_path;
  for (const ChangeEvent& e : evs) by_path[e.path] = &e;
  ASSERT_EQ(by_path.count("new/a.md"), 1u) << Describe(evs);
  ASSERT_EQ(by_path.count("new/b.md"), 1u) << Describe(evs);
  EXPECT_EQ(by_path["new/a.md"]->kind, ChangeKind::kMoved) << Describe(evs);
  EXPECT_EQ(by_path["new/b.md"]->kind, ChangeKind::kMoved) << Describe(evs);
  EXPECT_EQ(by_path["new/a.md"]->old_path, "old/a.md") << Describe(evs);
  EXPECT_EQ(by_path["new/b.md"]->old_path, "old/b.md") << Describe(evs);
}

}  // namespace
}  // namespace umbra
