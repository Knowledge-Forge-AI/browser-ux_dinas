(function () {
  "use strict";
  const Core = BrowserUxRailCore;
  const L = Core.LIMITS;
  // States remain isolated in the content-script world, never exported to page DOM.
  let state = "STARTING", sheetReady = false, ready = document.readyState !== "loading";
  let lifecyclePaused = false, pendingTopLayer = false, resumeAt = 0;
  let host = null, shadow = null, thickness = null, probe = null;
  let frame = 0, wake = 0, scanTimer = 0, heartbeat = 0;
  let wakeAt = Infinity;
  let scanCount = 0, scanCooldown = 0, lastRescan = -10000;
  const slowPasses = { scan: 0, layout: 0 };
  let refusedUntil = 0, refusedDelay = 30000, mutationDelay = 150, lastMutation = -10000;
  let recoveryAt = 0, externalHides = [], contest = false, drag = null, sequence = 0;
  let expectedClosed = false, detachedCounted = false, layoutCursor = 0, layoutRemaining = 0, activeCursor = 0;
  let shadowLimit = false, hitFailures = 0;
  const candidates = new Map(), rails = new Map(), geometry = new Map();
  const roots = new Set(), tasks = [], pending = new Set();
  const now = () => performance.now();
  const px = (n) => `${n}px`;
  function css(el, values) {
    for (const [name, value] of Object.entries(values)) el.style.setProperty(name, value, "important");
  }
  function flatParent(el) {
    return el.assignedSlot || el.parentElement || el.getRootNode()?.host || null;
  }
  function inert(el) {
    for (let n = el, i = 0; n && i < L.MAX_ANCESTORS; n = flatParent(n), i++) {
      if (n.hasAttribute("inert")) return true;
      if (i === L.MAX_ANCESTORS - 1 && flatParent(n)) return true;
    }
    return false;
  }
  // The bridge is a liveness/coverage contract, not an authentication boundary.
  const sentinelQuery = "browser-ux-scrollbars-sentinel-q";
  const sentinelState = "browser-ux-scrollbars-sentinel-s";
  const mainReasons = new Set(["ATTACH_SHADOW_UNAVAILABLE", "ATTACH_SHADOW_REPLACED",
    "ROOT_BUDGET_EXCEEDED", "ROOT_INSTRUMENTATION_FAILED", "SELECTOR_UNSUPPORTED",
    "WORK_BUDGET_EXCEEDED", "LATE_INSTALL", "DECLARATIVE_SHADOW_API", "CLONABLE_ROOT",
    "FOREIGN_REALM_ROOT", "UNCAPTURED_ROOT", "INSTRUMENTATION_LOST", "COVERAGE_PENDING", "ROOT_PENDING"]);
  let sentinel = "UNKNOWN", sentinelReason = "HANDSHAKE_MISSING", sentinelBound = false;
  let sentinelInstance = null, sentinelSeq = 0, sentinelEpoch = -1, sentinelSeen = -Infinity;
  let bridgePermanent = false, localCoverageLost = false, bridgeRequest = 0, lastReply = 0;
  let session = "", coverageTimer = 0, coverage = null, coveredEpoch = -1;
  let coverageWindow = now(), coverageWork = 0, coverageStarts = 0;
  let coverageEstablished = false, coverageRescan = true, coverageUntil = 0, coverageQueued = false;
  let coverageBlocked = false;
  let mainPermanent = false, mainActive = false, structuralDelay = 1000;
  const coverageAdded = new Set(), safetyObservers = new WeakMap(), detachedSubtrees = new WeakSet();
  let verifiedRoots = new WeakSet(), safetyRecordsThisCycle = 0;
  let transientClear = false;
  try {
    session = Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => n.toString(16).padStart(2, "0")).join("");
  } catch { bridgePermanent = true; sentinelReason = "BRIDGE_INVALID"; }
  const exactKeys = (message, keys) => message && typeof message === "object" && !Array.isArray(message) &&
    Object.keys(message).length === keys.length && keys.every((key) => Object.hasOwn(message, key));
  const integer = (n, min = 0) => Number.isSafeInteger(n) && n >= min;
  const hex = (s) => typeof s === "string" && /^[0-9a-f]{32}$/.test(s);
  function sentinelClear() {
    return !bridgePermanent && !localCoverageLost && !mainPermanent && !coverageRescan && now() >= coverageUntil &&
      sentinel === "CLEAR" && now() - sentinelSeen < L.SENTINEL_LIVENESS_MS;
  }
  function sentinelHide(reason) {
    sentinel = "UNKNOWN"; sentinelReason = reason; sentinelBound = false;
    cancelDrag();
    queueMicrotask(() => { if (!sentinelClear()) hide("SUSPENDED"); });
  }
  function sendSentinel(type, target = document, epoch = Math.max(0, sentinelEpoch)) {
    if (bridgePermanent || !session || bridgeRequest >= Number.MAX_SAFE_INTEGER) { sentinelHide("BRIDGE_INVALID"); return false; }
    const request = ++bridgeRequest;
    try {
      target.dispatchEvent(new CustomEvent(sentinelQuery, { detail: JSON.stringify({ v: 1, type, session, request, epoch }),
        bubbles: target !== document, composed: true }));
    } catch { sentinelHide("BRIDGE_INVALID"); return false; }
    return lastReply === request;
  }
  function coverageFail(reason) {
    localCoverageLost = true; coverage = null;
    if (coverageTimer) { clearTimeout(coverageTimer); coverageTimer = 0; }
    sentinelHide(reason); sendSentinel("lost");
  }
  // Safety coverage is separate from rail discovery. Lost root authority is
  // permanent; temporary work overruns suspend and recover through a full walk.
  const shadowHosts = new Set("article aside blockquote body div footer h1 h2 h3 h4 h5 h6 header main nav p section span".split(" "));
  function privilegedRoot(el) {
    if (!shadowHosts.has(el.localName) && !el.localName.includes("-")) return null;
    let root;
    if (typeof chrome.dom?.openOrClosedShadowRoot === "function") root = chrome.dom.openOrClosedShadowRoot(el);
    else if ("openOrClosedShadowRoot" in el) root = el.openOrClosedShadowRoot;
    else throw new Error("ROOT_VERIFY_UNAVAILABLE");
    if (root !== null && (!root || root.nodeType !== 11 || root.host !== el)) throw new Error("ROOT_VERIFY_UNAVAILABLE");
    return root;
  }
  function requestCoverage() {
    if (!ready || localCoverageLost || bridgePermanent || mainPermanent || mainActive ||
        now() - sentinelSeen >= L.SENTINEL_LIVENESS_MS || coverageBlocked || !coveragePending() || coverageTimer || !document.documentElement) return;
    coverageTimer = setTimeout(coverageSlice, Math.max(1, coverageUntil - now()));
  }
  function coveragePending() { return sentinelReason === "COVERAGE_PENDING" || sentinelReason === "ROOT_PENDING" || sentinelReason === "COVERAGE_THROTTLED"; }
  function coverageThrottle(structural = false) {
    if (localCoverageLost || bridgePermanent || mainPermanent) return;
    coverage = null; coverageRescan = true; coverageAdded.clear();
    // A local burst must neither erase liveness loss nor shorten a structural hold.
    coverageUntil = Math.max(coverageUntil, now() + structuralDelay);
    if (coverageTimer) { clearTimeout(coverageTimer); coverageTimer = 0; }
    if (structural) {
      coverageBlocked = true; structuralDelay = Math.min(30000, structuralDelay * 2);
      sentinelHide("COVERAGE_TREE_LIMIT"); // no automatic full-tree retry
    } else {
      if (!mainActive && now() - sentinelSeen < L.SENTINEL_LIVENESS_MS) sentinelHide("COVERAGE_THROTTLED");
      else { cancelDrag(); queueMicrotask(() => hide("SUSPENDED")); }
      requestCoverage();
    }
  }
  function queueCoverage() {
    if (coverageQueued) return;
    coverageQueued = true;
    queueMicrotask(() => {
      coverageQueued = false;
      if (!ready || localCoverageLost || bridgePermanent || mainPermanent || mainActive ||
          now() - sentinelSeen >= L.SENTINEL_LIVENESS_MS || coverageBlocked || !coveragePending()) return;
      if (now() < coverageUntil) { requestCoverage(); return; }
      if (coverageTimer) { clearTimeout(coverageTimer); coverageTimer = 0; }
      coverageSlice();
    });
  }
  // Verification grants permission to skip an interior. Withdraw it from every
  // enclosing shadow root whose fast path could hide this changed subtree.
  function unverify(node) {
    for (let root = node.getRootNode(); root.nodeType === 11 && root.host; root = root.host.getRootNode()) {
      verifiedRoots.delete(root); coverage?.roots.delete(root);
    }
  }
  function detachedPath(node) {
    if (!node.isConnected) return true;
    // Removal records retain disconnect history until connected coverage has
    // visited the subtree. Delivery-time isConnected alone loses that history
    // when a host reconnects before its root observer callback runs.
    for (let current = node; current; current = current.parentNode || current.host) {
      if (detachedSubtrees.has(current)) return true;
    }
    return false;
  }
  function safetyRecords(records, observed) {
    if (localCoverageLost || bridgePermanent || mainPermanent) return;
    // The observer, rather than the added node, retains the containing root
    // even when the added node has already been removed at delivery time.
    if (records.length && observed.host && (coverageRescan || detachedPath(observed.host))) unverify(observed);
    // Keep the shared-observer aggregate budget across one delivery cycle.
    if (!safetyRecordsThisCycle) queueMicrotask(() => { safetyRecordsThisCycle = 0; });
    safetyRecordsThisCycle += records.length;
    if (safetyRecordsThisCycle > 512) { coverageThrottle(); return; }
    let qualifying = false;
    for (const record of records) {
      if (record.target === host || host?.contains(record.target)) continue;
      if (record.addedNodes.length + record.removedNodes.length > 512) { coverageThrottle(); return; }
      if ([...record.addedNodes, ...record.removedNodes].some((node) => node !== host)) qualifying = true;
      for (const node of record.removedNodes) if (node.nodeType === 1 && node !== host) detachedSubtrees.add(node);
      for (const node of record.addedNodes) {
        if (node.nodeType === 1 && node !== host) coverageAdded.add(node);
        if (coverageAdded.size > 512) { coverageThrottle(); return; }
      }
    }
    if (coverageBlocked && qualifying) {
      coverageBlocked = false;
      if (!mainActive && now() - sentinelSeen < L.SENTINEL_LIVENESS_MS) sentinelHide("COVERAGE_PENDING");
    }
    queueCoverage();
  }
  function observeSafety(root) {
    if (safetyObservers.has(root)) return;
    const observer = new MutationObserver((records) => safetyRecords(records, root));
    observer.observe(root, { childList: true, subtree: true });
    safetyObservers.set(root, observer);
  }
  try { observeSafety(document); }
  catch { coverageFail("ROOT_INSTRUMENTATION_FAILED"); }
  function coverageSlice() {
    coverageTimer = 0;
    if (localCoverageLost || bridgePermanent || mainPermanent || mainActive ||
        now() - sentinelSeen >= L.SENTINEL_LIVENESS_MS || !coveragePending()) { coverage = null; return; }
    if (coverageBlocked) return;
    if (now() < coverageUntil) { requestCoverage(); return; }
    if (now() - coverageWindow >= 1000) { coverageWindow = now(); coverageWork = 0; coverageStarts = 0; }
    try {
      if (!coverage || coverage.epoch !== sentinelEpoch) {
        if (++coverageStarts > 64) { coverageThrottle(); return; }
        // Re-walk every unfinished task, including retained shadow interiors.
        // A full walk restarts conservatively; sustained large-page mutation can
        // delay completion, but the work/start budgets bound its cost.
        if (coverage) {
          if (coverage.full) coverageRescan = true;
          else for (const task of coverage.tasks) coverageAdded.add(task.root);
          if (coverageAdded.size > 512) coverageRescan = true;
        }
        coverage = { epoch: sentinelEpoch, nodes: 0, roots: new Set(), tasks: [], full: !coverageEstablished || coverageRescan };
        const root = document.documentElement;
        if (!root) { requestCoverage(); return; }
        if (!coverageEstablished || coverageRescan) {
          coverage.tasks.push({ root, walker: document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT), first: true });
        } else for (const node of coverageAdded) {
          if (node.isConnected) coverage.tasks.push({ root: node, walker: document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT), first: true });
          else unverify(node);
        }
        coverageAdded.clear();
      }
      const current = coverage, start = now(); let slice = 0;
      while (current.tasks.length && slice < L.SLICE_NODES && now() - start < L.SLICE_MS) {
        const task = current.tasks[0], el = task.first ? task.root : task.walker.nextNode(); task.first = false;
        if (!el) { current.tasks.shift(); continue; }
        if (++current.nodes > L.COVERAGE_WORK_NODES) { coverageThrottle(true); return; }
        if (++coverageWork > L.COVERAGE_WORK_NODES) { coverageThrottle(); return; }
        slice++;
        if (el.nodeType !== 1 || el === host) continue;
        if (el.isConnected) detachedSubtrees.delete(el);
        const root = privilegedRoot(el);
        if (!root || current.roots.has(root)) continue;
        if (current.roots.size >= L.COVERAGE_ROOTS) { coverageFail("COVERAGE_BUDGET_EXCEEDED"); return; }
        current.roots.add(root);
        if (!sendSentinel("verify", el, current.epoch)) { coverageFail("BRIDGE_INVALID"); return; }
        if (localCoverageLost || !coveragePending()) return;
        if (current.epoch !== sentinelEpoch) { coverage = null; coverageRescan = true; requestCoverage(); return; }
        if (coverageEstablished && !coverageRescan && verifiedRoots.has(root)) continue;
        observeSafety(root);
        current.tasks.push({ root, walker: document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT), first: true });
      }
      if (current.tasks.length) { requestCoverage(); return; }
      // An interrupted/disconnected interior must not become a trusted skip on
      // reconnection. Commit root verification only after every task completes.
      // A full walk replaces authority: unreachable roots omitted from it must
      // not preserve a stale skip after a throttled delta has been discarded.
      if (current.full) verifiedRoots = new WeakSet(current.roots);
      else for (const root of current.roots) verifiedRoots.add(root);
      coverage = null; coveredEpoch = current.epoch;
      coverageEstablished = true; coverageRescan = false;
      if (!sendSentinel("covered", document, current.epoch)) coverageFail("BRIDGE_INVALID");
      else if (sentinelClear()) structuralDelay = 1000;
    } catch (error) { coverageFail(error.message === "ROOT_VERIFY_UNAVAILABLE" ? error.message : "ROOT_INSTRUMENTATION_FAILED"); }
  }
  document.addEventListener(sentinelState, (event) => {
    if (bridgePermanent) return;
    let message;
    try {
      if (typeof event.detail !== "string" || event.detail.length > 768) throw new Error();
      message = JSON.parse(event.detail);
      if (exactKeys(message, ["v", "type"]) && message.v === 1 && message.type === "ready") { sendSentinel("request"); return; }
      if (!exactKeys(message, ["v", "type", "session", "instance", "seq", "epoch", "state", "reason", "bound", "reply"]) ||
          message.v !== 1 || message.type !== "state" || !hex(message.session) || message.session !== session || !hex(message.instance) ||
          !integer(message.seq, 1) || message.seq <= sentinelSeq || !integer(message.epoch) || message.epoch < sentinelEpoch ||
          !integer(message.reply) || message.reply > bridgeRequest || typeof message.bound !== "boolean" ||
          !["CLEAR", "ACTIVE", "UNKNOWN"].includes(message.state) ||
          (message.state === "UNKNOWN" ? !mainReasons.has(message.reason) : message.reason !== "NONE")) throw new Error();
      if (sentinelInstance && sentinelInstance !== message.instance) { bridgePermanent = true; throw new Error(); }
    } catch { sentinelHide("BRIDGE_INVALID"); return; }
    sentinelInstance = message.instance; sentinelSeq = message.seq; sentinelEpoch = message.epoch;
    sentinelSeen = now(); lastReply = message.reply;
    mainActive = message.state === "ACTIVE";
    if (message.state === "UNKNOWN" && !["WORK_BUDGET_EXCEEDED", "COVERAGE_PENDING", "ROOT_PENDING"].includes(message.reason)) mainPermanent = true;
    if (localCoverageLost) return;
    const wasClear = sentinelClear();
    if (wasClear && message.state === "UNKNOWN" && message.reason === "COVERAGE_PENDING") transientClear = true;
    sentinel = message.state; sentinelReason = message.reason; sentinelBound = message.bound;
    if (sentinelReason === "WORK_BUDGET_EXCEEDED" || sentinelReason === "ROOT_PENDING") { coverageRescan = true; coverageAdded.clear(); }
    if (sentinel === "CLEAR" && (coveredEpoch !== sentinelEpoch || coverageRescan)) { sentinelHide("COVERAGE_PENDING"); requestCoverage(); return; }
    if (!sentinelClear()) {
      // MutationObserver callbacks finish before these microtasks. A small
      // verified delta can restore CLEAR without cancelling an in-flight drag.
      if (coveragePending()) queueCoverage();
      else { transientClear = false; cancelDrag(); }
      queueMicrotask(() => { if (!sentinelClear()) { transientClear = false; hide("SUSPENDED"); } });
      if (coveragePending()) requestCoverage();
    } else if (!wasClear) {
      if (!transientClear) { resumeAt = now() + L.RESUME_DELAY_MS; schedule(L.RESUME_DELAY_MS); }
      transientClear = false;
    }
  });
  // Chrome 114–121 accepted :open syntax without implementing its semantics.
  // Keep USER native styling at the manifest floor; custom rails require 133.
  const chromeVersion = typeof navigator !== "undefined" && /(?:Chrome|Chromium)\/(\d+)/.exec(navigator.userAgent);
  if (chromeVersion && Number(chromeVersion[1]) < 133) {
    localCoverageLost = true; sentinelHide("SELECTOR_UNSUPPORTED");
  }
  sendSentinel("request");
  function sentinelHeartbeat() {
    if (now() - sentinelSeen >= L.SENTINEL_LIVENESS_MS) sentinelHide("SENTINEL_STALE");
    // Request also completes the handshake when MAIN arrived after ISOLATED.
    sendSentinel("request"); requestCoverage();
    setTimeout(sentinelHeartbeat, 1000);
  }
  setTimeout(sentinelHeartbeat, 1000);
  function suspended() {
    return !sentinelClear() || lifecyclePaused || document.visibilityState !== "visible" ||
      document.fullscreenElement || pendingTopLayer || shadowLimit || now() < refusedUntil;
  }
  function cancelDrag() {
    const previous = drag; drag = null;
    if (previous) {
      try { if (previous.thumb.hasPointerCapture(previous.id)) previous.thumb.releasePointerCapture(previous.id); } catch {}
    }
  }
  function clearRails() {
    cancelDrag();
    for (const [target, rail] of rails) { rail.box.remove(); resize.unobserve(target); }
    rails.clear(); geometry.clear();
  }
  function hide(reason) {
    state = reason; cancelDrag();
    if (host?.matches(":popover-open")) {
      expectedClosed = true;
      try { host.hidePopover(); } catch { schedule(16); }
    }
    if (heartbeat) { clearTimeout(heartbeat); heartbeat = 0; }
    clearRails();
    // Select pickers and shadow toggle events may have no observable close event.
    // A bounded hidden-state wake checks recovery without a per-frame loop.
    if (reason === "SUSPENDED" && !lifecyclePaused && document.visibilityState === "visible") schedule(L.POLL_SHOWN_MS);
  }
  function unexpectedClose() {
    if (contest || suspended() || now() < resumeAt) return;
    externalHides = externalHides.filter((t) => now() - t < 60000);
    externalHides.push(now());
    contest = externalHides.length >= 3;
    recoveryAt = now() + (externalHides.length === 1 ? 1000 : 30000);
    hide(contest ? "HOST_CONTESTED" : "HOST_RECOVERY");
    if (!contest) schedule(recoveryAt - now());
  }
  function topChange(event) {
    if (event.target === host) return;
    // beforetoggle is synchronous inside the page's algorithm; defer all API calls.
    if (event.type === "beforetoggle" && event.newState === "open") pendingTopLayer = true;
    resumeAt = now() + L.RESUME_DELAY_MS;
    queueMicrotask(() => { pendingTopLayer = false; if (suspended()) hide("SUSPENDED"); schedule(L.RESUME_DELAY_MS); });
  }
  function observeRoot(root) {
    if (roots.has(root)) return;
    if (roots.size >= L.MAX_SHADOWS) { shadowLimit = true; hide("SUSPENDED"); state = "LIMITED"; return; }
    roots.add(root); listen(root); mutation.observe(root, observerOptions);
    enqueue(root);
  }
  function listen(root) {
    root.addEventListener("beforetoggle", topChange, true);
    root.addEventListener("toggle", topChange, true);
    root.addEventListener("scroll", (event) => {
      const target = event.target === document ? document.scrollingElement : event.target;
      admit(target); schedule();
    }, { capture: true, passive: true });
    root.addEventListener("wheel", (event) => {
      let n = event.target;
      for (let i = 0; n?.nodeType === 1 && i < L.MAX_ANCESTORS; n = flatParent(n), i++) {
        if (potential(n)) { admit(n); schedule(); break; }
      }
    }, { capture: true, passive: true });
  }
  function potential(el) {
    if (!el || el.nodeType !== 1 || el === host || !el.isConnected) return false;
    if (el === document.scrollingElement) return true;
    const cs = getComputedStyle(el); // overflow before geometry or ancestor reads
    return cs.overflowY === "auto" || cs.overflowY === "scroll";
  }
  function admit(el) {
    if (!potential(el) || candidates.has(el)) return;
    if (candidates.size >= L.MAX_CANDIDATES) {
      state = "LIMITED";
      let victim = null;
      for (const [candidate, info] of candidates) {
        if (candidate !== document.scrollingElement && !rails.has(candidate)) {
          victim = candidate; if (!info.visible) break;
        }
      }
      if (!victim) return;
      candidates.delete(victim); geometry.delete(victim);
    }
    candidates.set(el, { order: sequence++, visible: false });
  }
  function enqueue(root) {
    if (!root || root === host || pending.has(root) || now() < scanCooldown) return;
    if (tasks.length >= L.MAX_PENDING) {
      state = "LIMITED"; scanCooldown = now() + L.LIMITED_COOLDOWN_MS;
      tasks.length = 0; pending.clear(); schedule(scanCooldown - now()); return;
    }
    pending.add(root);
    // Keep each walker across slices, including its root as the first visit.
    tasks.push({ root, walker: document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT), first: true });
    requestScan();
  }
  function requestScan() {
    if (!tasks.length || scanTimer || !ready || !sheetReady || lifecyclePaused || document.visibilityState !== "visible" || now() < refusedUntil || now() < scanCooldown) return;
    scanTimer = setTimeout(scanSlice, mutationDelay);
  }
  function scanSlice() {
    scanTimer = 0;
    if (lifecyclePaused || document.visibilityState !== "visible") return;
    const start = now(); let count = 0;
    while (tasks.length && count < L.SLICE_NODES && now() - start < L.SLICE_MS) {
      const task = tasks[0];
      const el = task.first ? task.root : task.walker.nextNode(); task.first = false;
      if (!el || !task.root.isConnected) { tasks.shift(); pending.delete(task.root); continue; }
      count++; scanCount++;
      if (scanCount >= L.SCAN_TOTAL) {
        state = "LIMITED"; scanCooldown = now() + L.LIMITED_COOLDOWN_MS;
        tasks.length = 0; pending.clear(); schedule(scanCooldown - now()); break;
      }
      if (el === host) continue;
      if (el.nodeType === 1) {
        admit(el);
        if (el.shadowRoot) observeRoot(el.shadowRoot);
      }
    }
    cost(now() - start, "scan");
    schedule();
    if (tasks.length && now() >= refusedUntil) requestScan();
  }
  function cost(duration, family) {
    slowPasses[family] = duration > L.PATHOLOGICAL_DURATION_MS ? slowPasses[family] + 1 : 0;
    if (slowPasses[family] < L.PATHOLOGICAL_PASSES) return;
    refusedUntil = now() + refusedDelay;
    refusedDelay = Math.min(L.REFUSED_COOLDOWN_MAX_MS, refusedDelay * 2);
    slowPasses[family] = 0; hide("REFUSED"); schedule(refusedUntil - now());
  }
  function schedule(delay = 0, continuing = false) {
    if (!continuing) layoutRemaining = Math.max(layoutRemaining, candidates.size);
    if (delay) {
      const deadline = now() + Math.max(1, delay);
      if (wake && wakeAt <= deadline) return;
      if (wake) clearTimeout(wake);
      wakeAt = deadline;
      wake = setTimeout(() => { wake = 0; wakeAt = Infinity; schedule(0, continuing); }, Math.max(1, delay)); return;
    }
    if (frame || !ready || !sheetReady) return;
    frame = requestAnimationFrame(() => { frame = 0; pass(); });
  }
  function neutralTransform(cs) {
    return Core.isIdentityTransform(cs.transform) && [cs.translate, cs.rotate, cs.scale].every((x) => !x || x === "none") && (!cs.zoom || Number(cs.zoom) === 1);
  }
  function rootGeometry(el, cs) {
    const html = document.documentElement, body = document.body;
    let overflow = getComputedStyle(html).overflowY;
    if (overflow === "visible" && body) overflow = getComputedStyle(body).overflowY;
    if (overflow === "hidden" || overflow === "clip" || inert(html) || (body && inert(body))) return null;
    if (el.scrollHeight - el.clientHeight <= 1) return null;
    const client = document.compatMode === "BackCompat" ? el.clientWidth : html.clientWidth;
    const width = window.innerWidth - client;
    if (!Core.validateGutter(width, thickness ?? width)) return null;
    // A private probe follows native side policy without trusting authored direction alone.
    let left = html.clientLeft >= width - 1 && html.clientLeft <= width + 1;
    if (probe) {
      css(probe, { direction: cs.direction === "rtl" ? "rtl" : "ltr" });
      left ||= probe.clientLeft >= width - 1;
    }
    const h = Math.min(el.clientHeight, window.innerHeight);
    if (h < L.MIN_TRACK) return null;
    return { target: el, root: true, depth: 0, left: left ? 0 : client, top: 0, width, height: h, fullTop: 0, fullHeight: h };
  }
  function nestedGeometry(el, cs) {
    if (cs.overflowY !== "auto" && cs.overflowY !== "scroll") return null;
    if (el.scrollHeight - el.clientHeight <= 1 || el.clientHeight < L.MIN_TRACK || !neutralTransform(cs)) return null;
    if (cs.clipPath && cs.clipPath !== "none") return null; // arbitrary clip geometry unproven
    const rect = el.getBoundingClientRect();
    if (Math.abs(rect.width / el.offsetWidth - 1) > .01 || Math.abs(rect.height / el.offsetHeight - 1) > .01) return null;
    const bl = parseFloat(cs.borderLeftWidth) || 0, br = parseFloat(cs.borderRightWidth) || 0;
    const gutter = el.offsetWidth - el.clientWidth - bl - br;
    if (!Core.validateGutter(gutter, thickness ?? gutter)) return null;
    const leftSide = el.clientLeft - bl > 1;
    const left = leftSide ? rect.left + bl : rect.left + el.clientLeft + el.clientWidth;
    const fullTop = rect.top + el.clientTop, fullHeight = el.clientHeight;
    let clip = { left, right: left + gutter, top: fullTop, bottom: fullTop + fullHeight };
    clip = Core.intersectRects(clip, { left: 0, right: window.innerWidth, top: 0, bottom: window.innerHeight });
    let depth = 0, n = flatParent(el), skipOverflow = cs.position === "fixed";
    let absoluteSkip = cs.position === "absolute" ? el.offsetParent : null;
    for (; n && depth < L.MAX_ANCESTORS; n = flatParent(n), depth++) {
      const p = getComputedStyle(n);
      if (n.hasAttribute("inert") || p.display === "none") return null;
      if (!neutralTransform(p)) return null;
      // A fixed box escapes overflow until an ancestor creates its containing block.
      const containing = (p.transform && p.transform !== "none") || /transform|perspective|filter|contain/.test(p.willChange || "") ||
        (p.contentVisibility && p.contentVisibility !== "visible") || (p.filter && p.filter !== "none") || (p.perspective && p.perspective !== "none") || /paint|layout|strict|content/.test(p.contain);
      if (containing) skipOverflow = false;
      if (n === absoluteSkip) absoluteSkip = null;
      if (n !== document.documentElement && p.clipPath && p.clipPath !== "none") return null;
      if (n !== document.documentElement && ((!skipOverflow && !absoluteSkip && (p.overflowX !== "visible" || p.overflowY !== "visible")) || /paint|strict|content/.test(p.contain))) {
        const r = n.getBoundingClientRect();
        const box = { left: r.left + n.clientLeft, right: r.left + n.clientLeft + n.clientWidth,
          top: r.top + n.clientTop, bottom: r.top + n.clientTop + n.clientHeight };
        // Axis-specific layout clips do not cut the other dimension.
        clip = Core.intersectRects(clip, {
          left: p.overflowX !== "visible" || /paint|strict|content/.test(p.contain) ? box.left : -Infinity,
          right: p.overflowX !== "visible" || /paint|strict|content/.test(p.contain) ? box.right : Infinity,
          top: p.overflowY !== "visible" || /paint|strict|content/.test(p.contain) ? box.top : -Infinity,
          bottom: p.overflowY !== "visible" || /paint|strict|content/.test(p.contain) ? box.bottom : Infinity,
        });
      }
    }
    if (n || clip.width < gutter - 1 || clip.height < L.MIN_TRACK) return null;
    return { target: el, root: false, depth: depth + 1, left: clip.left, top: clip.top, width: clip.width,
      height: clip.height, fullTop, fullHeight };
  }
  function evaluate(el) {
    if (!el.isConnected || inert(el)) return null;
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility !== "visible" ||
        !el.checkVisibility({ visibilityProperty: true, opacityProperty: el !== document.scrollingElement })) return null;
    return el === document.scrollingElement ? rootGeometry(el, cs) : nestedGeometry(el, cs);
  }
  function verifyHost() {
    const cs = getComputedStyle(host);
    return cs.display === "block" && cs.position === "fixed" && cs.pointerEvents === "none" &&
      cs.opacity === "1" && cs.visibility === "visible" && cs.transform === "none" &&
      (!cs.filter || cs.filter === "none") && (!cs.backdropFilter || cs.backdropFilter === "none") &&
      (!cs.clipPath || cs.clipPath === "none") && (!cs.maskImage || cs.maskImage === "none") &&
      parseFloat(cs.borderTopWidth) === 0 && parseFloat(cs.paddingTop) === 0 &&
      cs.backgroundColor === "rgba(0, 0, 0, 0)";
  }
  function createHost() {
    try {
      host = document.createElement("browser-ux-scrollbar-shell");
      host.popover = "manual"; host.setAttribute("aria-hidden", "true");
      shadow = host.attachShadow({ mode: "closed" });
      const observedHost = host;
      host.addEventListener("toggle", (event) => {
        if (host !== observedHost) return;
        if (event.newState !== "closed") { expectedClosed = false; return; }
        if (expectedClosed) { expectedClosed = false; return; }
        if (!host.matches(":popover-open")) { detachedCounted = !host.isConnected; unexpectedClose(); }
      });
      document.documentElement.appendChild(host);
      if (!sendSentinel("host", host)) { sentinelHide("BRIDGE_INVALID"); return false; }
      probe = document.createElement("div");
      css(probe, { all: "initial", position: "absolute", left: "-10000px", top: "0", width: "100px", height: "100px",
        overflow: "scroll", visibility: "hidden", "pointer-events": "none", "scrollbar-width": "auto", "scrollbar-color": "GrayText Canvas" });
      shadow.appendChild(probe); return true;
    } catch { state = "HOST_UNAVAILABLE"; host?.remove(); host = null; shadow = null; return false; }
  }
  function ensureOpen() {
    if (!sentinelClear()) return false;
    if (suspended() || contest || now() < resumeAt || now() < recoveryAt) return false;
    if (!host && !createHost()) return false;
    if (!host.isConnected) return false;
    if (!host.matches(":popover-open")) {
      expectedClosed = false;
      try { if (!sentinelClear() || !sentinelBound) return false; host.showPopover(); } catch { state = "HOST_UNAVAILABLE"; return false; }
    }
    if (!verifyHost()) { hide("HOST_STYLE_CONTESTED"); return false; }
    // Effective ancestor zoom can change after the first measurement.
    const ratio = probe.getBoundingClientRect().width / 100;
    if (ratio < .99 || ratio > 1.01) { hide("GEOMETRY_UNPROVEN"); return false; }
    if (thickness === null) {
      thickness = probe.offsetWidth - probe.clientWidth;
      if (thickness < L.MIN_THICKNESS || thickness > L.MAX_THICKNESS) {
        hide("PLATFORM_SCROLLBAR_THICKNESS_UNSUPPORTED"); return false;
      }
    }
    return true;
  }
  function pass() {
    if (!sheetReady || !ready || contest) return;
    if (suspended()) { hide(now() < refusedUntil ? "REFUSED" : "SUSPENDED"); return; }
    if (now() < resumeAt || now() < recoveryAt || now() < refusedUntil) {
      schedule(Math.max(resumeAt, recoveryAt, refusedUntil) - now()); return;
    }
    if (["HOST_STYLE_CONTESTED", "PLATFORM_SCROLLBAR_THICKNESS_UNSUPPORTED", "GEOMETRY_UNPROVEN", "HOST_UNAVAILABLE"].includes(state)) return;
    if (host && !host.isConnected) {
      if (!detachedCounted) unexpectedClose(); detachedCounted = false; if (contest) return;
      host = null; shadow = null; probe = null; thickness = null; schedule(recoveryAt - now()); return;
    }
    admit(document.scrollingElement);
    if (now() >= scanCooldown && scanCooldown) { scanCount = 0; scanCooldown = 0; state = "ACTIVE"; enqueue(document.documentElement); }
    requestScan();
    // Sentinel coverage owns top-layer safety even while ordinary rail
    // discovery is LIMITED. Keep proven rails during discovery backoff.
    if (tasks.length || scanCooldown) state = "LIMITED";
    const start = now(), list = [...candidates.keys()];
    // Active rails and root are checked first; the remaining candidates rotate.
    const active = [...rails.keys()];
    const priority = active.slice(activeCursor).concat(active.slice(0, activeCursor));
    activeCursor = active.length ? (activeCursor + 1) % active.length : 0;
    if (document.scrollingElement) priority.unshift(document.scrollingElement);
    const visit = [...new Set(priority)];
    for (let i = 0; i < Math.min(32, list.length); i++) visit.push(list[(layoutCursor + i) % list.length]);
    layoutCursor = list.length ? (layoutCursor + 32) % list.length : 0;
    // Keep last proven rectangles for active targets not reached in this slice.
    // Evaluated targets are replaced or removed; active order rotates fairly.
    for (const target of geometry.keys()) if (!target.isConnected) geometry.delete(target);
    layoutRemaining = Math.max(0, layoutRemaining - 32);
    for (const el of new Set(visit)) {
      if (now() - start >= L.SLICE_MS && el !== document.scrollingElement) { state = "LIMITED"; break; }
      const result = evaluate(el);
      if (result) { geometry.set(el, result); if (candidates.has(el)) candidates.get(el).visible = true; }
      else { geometry.delete(el); if (!el.isConnected) candidates.delete(el); }
    }
    const items = [...geometry.values()].filter((item) => item.target.isConnected);
    items.sort((a, b) => b.depth - a.depth || (candidates.get(a.target)?.order ?? 0) - (candidates.get(b.target)?.order ?? 0));
    if (items.length > L.MAX_RAILS) state = "LIMITED";
    const selected = items.slice(0, L.MAX_RAILS);
    cost(now() - start, "layout");
    if (now() < refusedUntil) return;
    if (!selected.length) { hide(state === "LIMITED" ? "LIMITED" : "IDLE"); if (layoutRemaining > 0) schedule(150, true); return; }
    if (!ensureOpen()) return;
    // Revalidate provisional gutters against the measured native probe.
    const valid = selected.filter((item) => Core.validateGutter(item.width, thickness));
    render(valid);
    if (!rails.size) return;
    if (!valid.length) { hide("IDLE"); return; }
    if (state !== "LIMITED") state = "ACTIVE";
    if (!heartbeat) heartbeat = setTimeout(() => { heartbeat = 0; schedule(0, true); }, L.POLL_SHOWN_MS);
    if (layoutRemaining > 0) schedule(150, true);
  }
  function render(items) {
    const keep = new Set(items.map((i) => i.target));
    for (const [target, info] of rails) if (!keep.has(target)) {
      if (drag?.target === target) cancelDrag(); info.box.remove(); rails.delete(target); resize.unobserve(target);
    }
    // Parents paint first; descendants get greater z-index independent of insertion order.
    for (const item of items) {
      let info = rails.get(item.target);
      if (!info) {
        const box = document.createElement("div"), track = document.createElement("div"), thumb = document.createElement("div");
        for (const el of [box, track, thumb]) {
          css(el, { all: "initial", display: "block", "box-sizing": "border-box", margin: "0", padding: "0", border: "0",
            "pointer-events": "auto", "touch-action": "none", "user-select": "none", "writing-mode": "horizontal-tb", direction: "ltr" });
        }
        css(box, { position: "absolute", overflow: "hidden", background: "Canvas" });
        css(track, { position: "absolute", background: "Canvas", left: "0", width: "100%" });
        css(thumb, { position: "absolute", background: "GrayText", left: "0", width: "100%" });
        track.appendChild(thumb); box.appendChild(track); shadow.appendChild(box);
        info = { box, track, thumb, target: item.target, item }; rails.set(item.target, info);
        interactions(info); resize.observe(item.target);
      }
      info.item = item;
      info.thumbGeometry = Core.computeThumbGeometry({ scrollSize: item.target.scrollHeight, clientSize: item.target.clientHeight,
        scrollPos: item.target.scrollTop, trackLength: item.fullHeight });
      css(info.box, { left: px(item.left), top: px(item.top), width: px(item.width), height: px(item.height), "z-index": String(item.depth + 1) });
      css(info.track, { top: px(item.fullTop - item.top), height: px(item.fullHeight) });
      css(info.thumb, { top: px(info.thumbGeometry.thumbOffset), height: px(info.thumbGeometry.thumbLength) });
    }
    // Failed routing is ambiguous: page top-layer UI and engine gutter behavior
    // can both cause it. Suspend the entire shell, never latch a root diagnosis.
    for (const rail of rails.values()) {
      const i = rail.item;
      try {
        const hit = shadow.elementFromPoint(i.left + i.width / 2, i.top + i.height / 2);
        if (!hit || ![...rails.values()].some((other) => other.box.contains(hit))) { routingUnconfirmed(); return; }
      } catch { routingUnconfirmed(); return; }
    }
    hitFailures = 0;
  }
  function routingUnconfirmed() {
    hitFailures++;
    recoveryAt = now() + (hitFailures === 1 ? L.POLL_SHOWN_MS : L.LIMITED_COOLDOWN_MS);
    hide("HIT_TEST_UNCONFIRMED"); schedule(recoveryAt - now());
  }
  function atPoint(fallback, event) {
    const overlapping = [...rails.values()].filter(({ item: i }) => event.clientX >= i.left && event.clientX <= i.left + i.width && event.clientY >= i.top && event.clientY <= i.top + i.height);
    if (overlapping.length < 2) return fallback;
    // Only competing scroller branches matter; decorative page overlays never suppress.
    const hits = document.elementsFromPoint(event.clientX, event.clientY).filter((hit) => hit !== host);
    for (const hit of hits) {
      const relevant = overlapping.filter((info) => info.target === hit || info.target.contains(hit));
      if (relevant.length) return relevant.sort((a, b) => b.item.depth - a.item.depth)[0];
    }
    return overlapping.sort((a, b) => b.item.depth - a.item.depth)[0] || fallback;
  }
  function safeInteraction(info, event) {
    if (suspended() || !host?.matches(":popover-open")) { cancelDrag(); schedule(); return null; }
    try {
      if (![...rails.values()].some((rail) => rail.box.contains(shadow.elementFromPoint(event.clientX, event.clientY)))) {
        cancelDrag(); schedule(); return null;
      }
    } catch { cancelDrag(); schedule(); return null; }
    const selected = atPoint(info, event);
    if (inert(selected.target) || !selected.target.isConnected) return null;
    return selected;
  }
  function consume(event) { event.preventDefault(); event.stopImmediatePropagation(); }
  function interactions(info) {
    info.thumb.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      const target = safeInteraction(info, event); if (!target) return;
      consume(event); cancelDrag();
      try { info.thumb.setPointerCapture(event.pointerId); } catch { return; }
      drag = { thumb: info.thumb, id: event.pointerId, target: target.target, startY: event.clientY,
        startScroll: target.target.scrollTop, travel: target.thumbGeometry.trackTravel, range: target.thumbGeometry.scrollRange };
    });
    info.thumb.addEventListener("pointermove", (event) => {
      if (!drag || drag.id !== event.pointerId) return;
      // Eligibility passes own selector-query cost; drag frames use lifecycle
      // flags and a local hit-test so whole-document queries are not per-move.
      let routed = false;
      try {
        const i = info.item, hit = shadow.elementFromPoint(i.left + i.width / 2, i.top + i.height / 2);
        routed = [...rails.values()].some((rail) => rail.box.contains(hit));
      } catch {}
      if (!sentinelClear() || !routed || pendingTopLayer || lifecyclePaused || document.visibilityState !== "visible" || document.fullscreenElement || inert(drag.target)) { cancelDrag(); schedule(); return; }
      consume(event);
      if (drag.travel > 0) drag.target.scrollTop = Core.clamp(drag.startScroll + (event.clientY - drag.startY) * drag.range / drag.travel, 0, drag.range);
      schedule();
    });
    for (const type of ["pointerup", "pointercancel", "lostpointercapture"]) info.thumb.addEventListener(type, (event) => {
      if (drag?.id === event.pointerId) cancelDrag();
    });
    info.track.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 || event.target === info.thumb) return;
      const target = safeInteraction(info, event); if (!target) return;
      consume(event);
      const delta = Core.computeTrackStep({ clickOffset: event.clientY - target.item.fullTop,
        thumbOffset: target.thumbGeometry.thumbOffset, thumbLength: target.thumbGeometry.thumbLength, clientLength: target.target.clientHeight });
      target.target.scrollTop += delta.stepDelta; schedule();
    });
    info.box.addEventListener("wheel", (event) => {
      const target = safeInteraction(info, event); if (!target) return;
      consume(event);
      const delta = Core.computeWheelScroll({ deltaMode: event.deltaMode, deltaY: event.deltaY, clientHeight: target.target.clientHeight });
      target.target.scrollTop += delta.scrollDeltaY; schedule();
    }, { passive: false });
  }
  const resize = new ResizeObserver(() => schedule());
  const observerOptions = { childList: true, subtree: true, attributes: true, attributeFilter: ["open", "popover", "inert", "hidden", "class", "style"] };
  const mutation = new MutationObserver((records) => {
    let visited = 0;
    for (const record of records) {
      if (record.target === host || host?.contains(record.target)) continue;
      if (++visited > L.MAX_PENDING) {
        state = "LIMITED";
        if (now() - lastRescan >= 10000) { lastRescan = now(); enqueue(document.documentElement); }
        mutationDelay = Math.min(5000, mutationDelay * 2); break;
      }
      if (record.type === "attributes") {
        admit(record.target);
        if (record.target.shadowRoot) observeRoot(record.target.shadowRoot);
        // Class/style may change descendant overflow. Bound that rediscovery
        // separately from the cheap recheck of already tracked targets.
        if (["class", "style"].includes(record.attributeName) && now() - lastRescan >= 10000 && !tasks.length) {
          lastRescan = now(); scanCount = 0; enqueue(record.target);
        }
      }
      for (let i = 0; record.addedNodes && i < record.addedNodes.length && i < L.MAX_PENDING; i++) {
        if (record.addedNodes[i].nodeType === 1) enqueue(record.addedNodes[i]);
      }
    }
    if (now() - lastMutation < 150) mutationDelay = Math.min(5000, mutationDelay * 2);
    else if (now() - lastMutation > 5000) mutationDelay = 150;
    lastMutation = now();
    const urgent = records.some((r) => r.type === "attributes" && ["open", "popover", "inert", "hidden"].includes(r.attributeName));
    schedule(urgent ? 0 : mutationDelay); requestScan();
  });
  // Native USER hardening is requested even when the top-layer feature is absent.
  let timeout = setTimeout(() => { timeout = 0; state = "USER_SHEET_UNCONFIRMED"; }, L.TIMEOUT_MS);
  try {
    chrome.runtime.sendMessage("browser-ux-scrollbars", (reply) => {
      if (!timeout) return;
      clearTimeout(timeout); timeout = 0;
      if (chrome.runtime.lastError || reply?.ok !== true) { state = "USER_SHEET_UNCONFIRMED"; return; }
      if (document.contentType !== "text/html" || typeof HTMLElement.prototype.showPopover !== "function" ||
          typeof HTMLElement.prototype.hidePopover !== "function" || !("popover" in HTMLElement.prototype) ||
          !CSS.supports("selector(:popover-open)") || !CSS.supports("selector(:modal)")) { state = "TOP_LAYER_UNAVAILABLE"; return; }
      sheetReady = true; if (ready) start();
    });
  } catch { clearTimeout(timeout); timeout = 0; state = "USER_SHEET_UNCONFIRMED"; }
  function start() {
    listen(document); mutation.observe(document.documentElement, observerOptions);
    enqueue(document.documentElement); admit(document.scrollingElement); schedule();
  }
  document.addEventListener("DOMContentLoaded", () => { ready = true; requestCoverage(); if (sheetReady) start(); }, { once: true });
  document.addEventListener("fullscreenchange", () => { resumeAt = now() + L.RESUME_DELAY_MS; queueMicrotask(() => { if (suspended()) hide("SUSPENDED"); schedule(L.RESUME_DELAY_MS); }); });
  document.addEventListener("visibilitychange", () => { sendSentinel("request"); resumeAt = now() + L.RESUME_DELAY_MS; if (suspended()) hide("SUSPENDED"); else { requestScan(); schedule(L.RESUME_DELAY_MS); } });
  window.addEventListener("pagehide", () => { lifecyclePaused = true; hide("SUSPENDED"); });
  window.addEventListener("pageshow", () => { sendSentinel("request"); lifecyclePaused = false; resumeAt = now() + L.RESUME_DELAY_MS; requestScan(); schedule(L.RESUME_DELAY_MS); });
  document.addEventListener("freeze", () => { lifecyclePaused = true; hide("SUSPENDED"); });
  document.addEventListener("resume", () => { lifecyclePaused = false; resumeAt = now() + L.RESUME_DELAY_MS; requestScan(); schedule(L.RESUME_DELAY_MS); });
  document.addEventListener("load", () => schedule(), true);
  document.fonts?.addEventListener("loadingdone", () => schedule());
  window.addEventListener("resize", () => schedule());
})();
