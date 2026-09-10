// The onboarding flow and search, screen by screen.
//
// No state is persisted yet beyond what the binaries themselves write. The
// passphrase is held in memory for the session and never written by this file:
// the vault's own keys live in <vault>/.umbra and the device key lives outside
// the vault entirely, which is the app's business to explain and not to manage.
// No bundler. Tauri exposes its API on the window when withGlobalTauri is set,
// which keeps the frontend a plain page with no build step -- worth having while
// the shape is still moving.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { open } = window.__TAURI__.dialog;

const app = document.getElementById("app");
const state = {
  screen: "welcome",
  vault: null,
  notes: 0,
  index: null,
  passphrase: "",
  model: "",
  built: null,
  progress: null,
  error: null,
};

const h = (html) => { app.innerHTML = html; };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function go(screen) { state.screen = screen; render(); }

// ---------------------------------------------------------------- screens

function welcome() {
  h(`<h1>Umbra</h1>
     <p>Search your notes. Everything stays on this machine — the notes, the
        model, and the index.</p>
     <button id="pick">Choose your notes folder</button>`);
  document.getElementById("pick").onclick = pickFolder;
}

async function pickFolder() {
  const dir = await open({ directory: true, multiple: false });
  if (!dir) return;
  state.vault = dir;
  state.notes = await invoke("count_notes", { folder: dir });
  state.index = null;
  go("folder");
}

function folder() {
  const none = state.notes === 0;
  h(`<h1>${esc(state.vault.split("/").pop())}</h1>
     <p class="tight">${none
        ? `No markdown files here.`
        : `<b>${state.notes.toLocaleString()}</b> markdown file${state.notes === 1 ? "" : "s"} found.`}</p>
     <p class="muted">${none
        ? `Umbra indexes <code>.md</code> files. Folders beginning with a dot,
           like <code>.obsidian</code> and <code>.trash</code>, are skipped.`
        : `Folders beginning with a dot are skipped, so Obsidian's own
           <code>.obsidian</code> and <code>.trash</code> are left alone.`}</p>
     <div class="row">
       <button id="back" class="secondary">Choose another</button>
       <button id="next" ${none ? "disabled" : ""}>Continue</button>
     </div>`);
  document.getElementById("back").onclick = pickFolder;
  if (!none) document.getElementById("next").onclick = () => go("passphrase");
}

function passphrase() {
  h(`<h1>Choose a passphrase</h1>
     <p class="tight">This protects the <b>search index</b> and syncing between
        your devices.</p>
     <div class="card">
       <h2>Your notes are not encrypted by this</h2>
       <p class="muted" style="margin:0">They stay as ordinary markdown files in
          your folder, readable by any editor. If you forget this passphrase your
          notes are still there — you would set up search again from scratch, and
          re-pair any other devices. There is no way to recover it, and there
          cannot be one.</p>
     </div>
     <p class="tight"><label for="p1">Passphrase</label></p>
     <p class="tight"><input type="password" id="p1" autocomplete="new-password"></p>
     <p class="tight"><label for="p2">Again</label></p>
     <p class="tight"><input type="password" id="p2" autocomplete="new-password"></p>
     <p class="muted" id="hint">&nbsp;</p>
     <div class="row">
       <button id="back" class="secondary">Back</button>
       <button id="next" disabled>Create the vault</button>
     </div>`);
  const p1 = document.getElementById("p1"), p2 = document.getElementById("p2");
  const next = document.getElementById("next"), hint = document.getElementById("hint");
  const check = () => {
    const a = p1.value, b = p2.value;
    let msg = "&nbsp;", ok = false;
    if (a.length > 0 && a.length < 12) msg = "At least 12 characters. A short passphrase is the weak link in all of this.";
    else if (a.length >= 12 && b.length > 0 && a !== b) msg = "These do not match.";
    else if (a.length >= 12 && a === b) { msg = "&nbsp;"; ok = true; }
    hint.innerHTML = msg;
    next.disabled = !ok;
  };
  p1.oninput = check; p2.oninput = check;
  document.getElementById("back").onclick = () => go("folder");
  next.onclick = async () => {
    state.passphrase = p1.value;
    next.disabled = true; next.textContent = "Creating…";
    try {
      await invoke("create_vault", { vault: state.vault, passphrase: state.passphrase });
      go("indexing");
      startIndex();
    } catch (e) {
      state.error = String(e);
      go("folder");
    }
  };
}

function indexing() {
  const p = state.progress;
  const pct = p && p.of ? Math.round((p.files / p.of) * 100) : 0;
  h(`<h1>Reading your notes</h1>
     <p class="tight">This happens once. You can search as soon as the first
        results land — it fills in as it goes.</p>
     <div class="bar"><i style="width:${pct}%"></i></div>
     <p class="muted">${p
        ? `${p.files.toLocaleString()} of ${p.of.toLocaleString()} notes ·
           ${p.chunks.toLocaleString()} passages · ${p.seconds.toFixed(0)}s`
        : "Starting…"}</p>
     ${state.error ? `<p class="warn">${esc(state.error)}</p>` : ""}`);
}

function search() {
  const b = state.built;
  h(`<h1>Search</h1>
     <p class="muted">${b ? `${b.vectors.toLocaleString()} passages from
        ${b.objects.toLocaleString()} notes.` : ""}</p>
     <div class="searchbar">
       <input type="text" id="q" placeholder="Ask about your notes" autofocus>
       <button id="go">Search</button>
     </div>
     <p class="muted" id="meta">&nbsp;</p>
     <div id="results"></div>`);
  const q = document.getElementById("q");
  const run = async () => {
    const question = q.value.trim();
    if (!question) return;
    document.getElementById("meta").textContent = "Searching…";
    try {
      const raw = await invoke("ask", {
        vault: state.vault, index: state.index, model: state.model,
        passphrase: state.passphrase, question, floor: "0.25",
      });
      renderResults(JSON.parse(raw));
    } catch (e) {
      document.getElementById("meta").innerHTML =
        `<span class="warn">${esc(String(e))}</span>`;
    }
  };
  document.getElementById("go").onclick = run;
  q.onkeydown = (e) => { if (e.key === "Enter") run(); };
}

function renderResults(r) {
  const meta = document.getElementById("meta");
  const results = document.getElementById("results");

  // THE STATUS IS RENDERED, NOT FLATTENED. The difference between "nothing was
  // near enough" and "the model read these and said they do not answer it" is
  // the difference the whole retrieval design turns on, and collapsing both to
  // "no results" would throw it away at the last step.
  const notice = {
    "no-passages": "Nothing in your notes is close enough to answer that.",
    "no-answer-in-passages":
      "These passages came back, and they do not answer the question.",
    ungrounded:
      "The model answered without using these passages. Treat it as the model talking, not your notes.",
  }[r.status];

  meta.innerHTML = `${r.passages.length} of ${r.vault_passages.toLocaleString()}
    passages · ${r.seconds.toFixed(2)}s${r.complete ? "" : ` · still indexing`}`;

  results.innerHTML =
    (notice ? `<div class="notice">${esc(notice)}</div>` : "") +
    (r.text && r.status === "answered"
      ? `<div class="card">${esc(r.text)}</div>` : "") +
    (r.passages.length === 0
      ? `<p class="muted">Nothing to show.</p>`
      : r.passages.map((p) => `
        <div class="hit">
          <div class="where"><span class="score">${p.score.toFixed(3)}</span>
            &nbsp; ${esc(p.path)}<span class="muted">:${p.start}-${p.end}</span>
            ${p.heading ? ` · ${esc(p.heading)}` : ""}</div>
          <div class="snip">${esc(p.text.slice(0, 320))}${p.text.length > 320 ? "…" : ""}</div>
        </div>`).join(""));
}

// ---------------------------------------------------------------- driving

async function startIndex() {
  state.index = `${state.vault}/.umbra/index`;
  const [path, there] = await invoke("model_status");
  if (!there) {
    state.error = `The search model is not installed yet. Expected it at ${path}`;
    go("nomodel");
    return;
  }
  state.model = path;
  try {
    const last = await invoke("build_index", {
      vault: state.vault, index: state.index,
      model: state.model, passphrase: state.passphrase,
    });
    const done = JSON.parse(last);
    if (done.event === "built") { state.built = done; go("search"); }
  } catch (e) {
    state.error = String(e);
    render();
  }
}

listen("index-progress", (e) => {
  try {
    const ev = JSON.parse(e.payload);
    if (ev.event === "progress") { state.progress = ev; if (state.screen === "indexing") render(); }
  } catch { /* a line that is not an event is not this screen's business */ }
});

// A MISSING MODEL IS A SCREEN, NOT AN ERROR IN A SUBPROCESS. Until the
// downloader exists this is where a fresh machine lands, and it should say what
// is missing and where it goes rather than failing somewhere the user cannot
// see.
function nomodel() {
  h(`<h1>One more thing to fetch</h1>
     <p>Umbra searches with a small model that runs on this machine. It is
        about 44 MB and is downloaded once.</p>
     <div class="card"><p class="muted" style="margin:0">Not yet wired up. The
        file is expected at:<br><code>${esc(state.error.split("at ").pop())}</code></p></div>
     <button id="back" class="secondary">Back</button>`);
  document.getElementById("back").onclick = () => go("folder");
}

function render() {
  ({ welcome, folder, passphrase, indexing, search, nomodel })[state.screen]();
}
render();
