(function () {
  "use strict";
  // MAIN has no extension API authority. Messages contain coarse state only.
  const apply = Reflect.apply, descriptor = Object.getOwnPropertyDescriptor;
  const define = Object.defineProperty, parse = JSON.parse, stringify = JSON.stringify;
  const add = EventTarget.prototype.addEventListener, dispatch = EventTarget.prototype.dispatchEvent;
  const stop = Event.prototype.stopPropagation, Custom = CustomEvent, NativeEvent = Event;
  const docQuery = Document.prototype.querySelector, docAll = Document.prototype.querySelectorAll;
  const fragmentQuery = DocumentFragment.prototype.querySelector;
  const elementQuery = Element.prototype.querySelector;
  const matches = Element.prototype.matches, rootOf = Node.prototype.getRootNode;
  const contains = Node.prototype.contains, nativeNow = performance.now.bind(performance);
  const later = setTimeout, microtask = queueMicrotask, NativeWeakRef = WeakRef;
  const Observer = MutationObserver, observe = MutationObserver.prototype.observe;
  const q = "browser-ux-scrollbars-sentinel-q", s = "browser-ux-scrollbars-sentinel-s";
  const MAX_ROOTS = 256, MAX_RECOMPUTES = 512, MAX_CALLBACKS = 240, MAX_RECORDS = 512;
  const rootRefs = new Set(), rootSeen = new WeakSet(), capturedHosts = new WeakSet();
  const integrity = [], rootInfo = new WeakMap();
  const pickerRoots = new Set();
  let session = null, boundHost = null, seq = 0, epoch = 0, covered = false;
  let coverageReason = "COVERAGE_PENDING";
  let permanent = null, pendingFlush = false, pickerPending = false, selfAck = false;
  let workUntil = 0, recoveryTimer = 0, workDelay = 1000;
  let windowStart = nativeNow(), recomputes = 0, callbacks = 0, queryTime = 0;
  const instance = Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => n.toString(16).padStart(2, "0")).join("");
  const documentInfo = { ref: new NativeWeakRef(document), active: false, dirty: true, select: false };
  rootInfo.set(document, documentInfo);
  function latch(reason) {
    if (permanent) return;
    permanent = reason; pushState();
  }
  function budget() {
    if (nativeNow() - windowStart >= 1000) {
      windowStart = nativeNow(); recomputes = 0; callbacks = 0; queryTime = 0;
    }
  }
  function throttle() {
    if (permanent || workUntil > nativeNow()) return;
    const delay = workDelay; workDelay = Math.min(30000, workDelay * 2);
    workUntil = nativeNow() + delay;
    for (const info of infos()) info.dirty = true;
    invalidate();
    if (!recoveryTimer) recoveryTimer = later(() => {
      recoveryTimer = 0; workUntil = 0; budget(); flush();
    }, delay);
  }
  function intact() {
    for (const [target, name, wrapper] of integrity) {
      if (descriptor(target, name)?.value !== wrapper) { latch(name === "attachShadow" ? "ATTACH_SHADOW_REPLACED" : "INSTRUMENTATION_LOST"); return false; }
    }
    if (HTMLElement.prototype !== Element.prototype && descriptor(HTMLElement.prototype, "attachShadow")) {
      latch("ATTACH_SHADOW_REPLACED"); return false;
    }
    return !permanent;
  }
  function infos() { return [documentInfo, ...rootRefs]; }
  function externalState() {
    if (permanent) return ["UNKNOWN", permanent];
    if (workUntil > nativeNow()) return ["UNKNOWN", "WORK_BUDGET_EXCEEDED"];
    // Lost coverage always dominates cached activity; only exact epoch completion clears it.
    if (!covered) return ["UNKNOWN", coverageReason];
    if (pickerPending || infos().some((info) => info.active)) return ["ACTIVE", "NONE"];
    return ["CLEAR", "NONE"];
  }
  function pushState(reply = 0) {
    if (!session) return;
    if (seq >= Number.MAX_SAFE_INTEGER || epoch >= Number.MAX_SAFE_INTEGER) permanent ||= "INSTRUMENTATION_LOST";
    const [state, reason] = externalState();
    const detail = stringify({ v: 1, type: "state", session, instance, seq: ++seq, epoch, state, reason,
      bound: !!boundHost?.isConnected, reply });
    try { apply(dispatch, document, [new Custom(s, { detail })]); } catch {}
  }
  function invalidate(reason = "COVERAGE_PENDING") {
    epoch++; covered = false;
    if (reason === "ROOT_PENDING" || coverageReason !== "ROOT_PENDING") coverageReason = reason;
    pushState();
  }
  function owned(target) { return target === boundHost || (boundHost && apply(contains, boundHost, [target])); }
  function recompute(info) {
    if (permanent || workUntil > nativeNow()) return;
    const root = info.ref.deref();
    if (!root) { rootRefs.delete(info); return; }
    budget();
    if (++recomputes > MAX_RECOMPUTES) { throttle(); return; }
    const start = nativeNow();
    try {
      if (root === document) {
        info.active = !!apply(docQuery, root, [":modal, select:open"]);
        if (!info.active) {
          const first = apply(docQuery, root, [":popover-open"]);
          if (first && first !== boundHost) info.active = true;
          else if (first) {
            const all = apply(docAll, root, [":popover-open"]);
            if (all.length > MAX_RECORDS) { throttle(); return; }
            for (const el of all) if (el !== boundHost) { info.active = true; break; }
          }
        }
      } else info.active = !!apply(fragmentQuery, root, [":modal, :popover-open, select:open"]);
      info.dirty = false;
    } catch { latch("SELECTOR_UNSUPPORTED"); }
    queryTime += nativeNow() - start;
    if (queryTime > 12) throttle();
  }
  function flush() {
    pendingFlush = false;
    if (!intact()) return;
    for (const info of infos()) if (info.dirty) recompute(info);
    pushState();
  }
  function scheduleFlush() {
    if (pendingFlush || permanent) return;
    pendingFlush = true; microtask(flush);
  }
  function transition(info, event) {
    if (owned(event.target)) return;
    if (event.newState === "open") { info.active = true; pushState(); }
    info.dirty = true; scheduleFlush();
  }
  function pickerWake(event) {
    if (permanent || (event && owned(event.target))) return;
    const target = event?.target;
    if (target?.localName !== "select") return;
    if (event.type === "keydown" && ![" ", "Enter", "ArrowDown", "ArrowUp", "F4"].includes(event.key)) return;
    const info = rootInfo.get(apply(rootOf, target, []));
    if (!info) { latch("ROOT_INSTRUMENTATION_FAILED"); return; }
    // Native select activation can lack toggle events. Wake only its root.
    pickerRoots.add(info);
    if (pickerPending) return;
    pickerPending = true; pushState();
    later(() => {
      pickerPending = false;
      for (const pending of pickerRoots) pending.dirty = true;
      pickerRoots.clear();
      flush();
    }, 50);
  }
  const mutation = new Observer((records) => {
    if (permanent) return;
    const mutationStart = nativeNow();
    budget();
    if (++callbacks > MAX_CALLBACKS || records.length > MAX_RECORDS) { throttle(); return; }
    if (workUntil > nativeNow()) return;
    let changed = false;
    for (const record of records) {
      if (owned(record.target)) continue;
      // Binding occurs synchronously before the host's insertion record delivers.
      if (record.type === "childList" && record.addedNodes.length + record.removedNodes.length > MAX_RECORDS) {
        throttle(); return;
      }
      if (record.type === "childList" && [...record.addedNodes, ...record.removedNodes].every((node) => node === boundHost)) continue;
      const root = apply(rootOf, record.target, []);
      const info = rootInfo.get(root);
      if (info) {
        // Text/feed updates do not require whole-root top-layer queries.
        // Insertion of interaction elements and removal of cached active UI do.
        let relevant = record.type === "attributes" || info.active;
        if (record.type === "childList") {
          try {
            relevant ||= record.target.nodeType === 1 && apply(matches, record.target, ["dialog, select, [popover]"]);
            for (const node of record.addedNodes) {
              if (node.nodeType === 1 && (apply(matches, node, ["dialog, select, [popover]"]) ||
                  apply(elementQuery, node, ["dialog, select, [popover]"]))) { relevant = true; break; }
            }
          } catch { latch("SELECTOR_UNSUPPORTED"); return; }
        }
        if (relevant) info.dirty = true;
        if (record.type === "attributes" && record.attributeName === "open" && record.target.hasAttribute("open")) {
          info.active = true; pushState();
        }
      }
      if (record.type === "childList") changed = true;
    }
    if (changed) invalidate();
    queryTime += nativeNow() - mutationStart;
    if (queryTime > 12) throttle();
    scheduleFlush();
  });
  function instrument(root, info) {
    apply(add, root, [q, handleRootQ, false]);
    for (const type of ["beforetoggle", "toggle"]) apply(add, root, [type, (event) => transition(info, event), true]);
    for (const type of ["pointerdown", "keydown"]) apply(add, root, [type, pickerWake, { capture: true, passive: true }]);
    apply(observe, mutation, [root, { childList: true, subtree: true, attributes: true, attributeFilter: ["open", "inert", "popover"] }]);
  }
  function registerRoot(root, host) {
    if (rootSeen.has(root) || permanent) return;
    if (rootRefs.size >= MAX_ROOTS) { latch("ROOT_BUDGET_EXCEEDED"); return; }
    const info = { ref: new NativeWeakRef(root), active: false, dirty: true, select: false };
    rootSeen.add(root); capturedHosts.add(host); rootRefs.add(info); rootInfo.set(root, info);
    try {
      instrument(root, info);
      if (root.clonable) { latch("CLONABLE_ROOT"); return; }
      recompute(info); invalidate("ROOT_PENDING");
    } catch { latch("ROOT_INSTRUMENTATION_FAILED"); }
  }
  function handleRootQ(event) {
    let data;
    try {
      if (typeof event.detail !== "string" || event.detail.length > 768) return;
      data = parse(event.detail);
      const keys = ["v", "type", "session", "request", "epoch"];
      if (!data || typeof data !== "object" || Object.keys(data).length !== keys.length || !keys.every((key) => Object.hasOwn(data, key)) ||
          data.v !== 1 || !["request", "host", "verify", "covered", "lost"].includes(data.type) ||
          typeof data.session !== "string" || !/^[0-9a-f]{32}$/.test(data.session) ||
          !Number.isSafeInteger(data.request) || data.request <= 0 || !Number.isSafeInteger(data.epoch) || data.epoch < 0) return;
    } catch { return; }
    if (session && session !== data.session) return;
    session ||= data.session;
    intact();
    const target = event.target;
    if (data.type === "verify" || data.type === "host") {
      apply(stop, event, []);
      if (data.type === "verify") {
        if (!capturedHosts.has(target)) {
          if (target?.shadowRoot) registerRoot(target.shadowRoot, target);
          else latch("UNCAPTURED_ROOT");
        }
      } else if (target?.localName === "browser-ux-scrollbar-shell" && target.isConnected &&
          apply(rootOf, target, []) === document && !apply(matches, target, [":popover-open"])) {
        boundHost = target; documentInfo.dirty = true;
      }
    } else if (target === document) {
      if (data.type === "covered" && data.epoch === epoch && document.readyState !== "loading" && workUntil <= nativeNow()) {
        // Includes preexisting active content in all newly registered roots.
        for (const info of infos()) if (info.dirty) recompute(info);
        if (infos().every((info) => !info.dirty) && !permanent && workUntil <= nativeNow()) {
          covered = true; coverageReason = "COVERAGE_PENDING"; workDelay = 1000;
        }
      } else if (data.type === "lost") latch("INSTRUMENTATION_LOST");
    } else return;
    pushState(data.request);
  }
  function wrapMethod(target, name, signal) {
    const desc = descriptor(target, name);
    if (!desc) return;
    if (typeof desc.value !== "function") { latch("ROOT_INSTRUMENTATION_FAILED"); return; }
    const original = desc.value;
    const wrapper = { [name](arg) { signal(this); return apply(original, this, arguments); } }[name];
    try { define(target, name, { ...desc, value: wrapper }); integrity.push([target, name, wrapper]); }
    catch { latch("ROOT_INSTRUMENTATION_FAILED"); }
  }
  // Install even in late documents; never reread page options after native code.
  const attachDescriptor = descriptor(Element.prototype, "attachShadow");
  if (!attachDescriptor || typeof attachDescriptor.value !== "function") latch("ATTACH_SHADOW_UNAVAILABLE");
  else {
    const original = attachDescriptor.value;
    const wrappedAttachShadow = { attachShadow(init) {
      const root = apply(original, this, arguments);
      try {
        if (this.ownerDocument !== document || root.ownerDocument !== document) latch("FOREIGN_REALM_ROOT");
        else registerRoot(root, this);
      } catch { latch("ROOT_INSTRUMENTATION_FAILED"); }
      return root;
    } }.attachShadow;
    try { define(Element.prototype, "attachShadow", { ...attachDescriptor, value: wrappedAttachShadow });
      integrity.push([Element.prototype, "attachShadow", wrappedAttachShadow]);
    } catch { latch("ATTACH_SHADOW_UNAVAILABLE"); }
  }
  for (const target of [Element.prototype, ShadowRoot.prototype]) {
    for (const name of ["setHTMLUnsafe", "setHTML"]) wrapMethod(target, name, () => latch("DECLARATIVE_SHADOW_API"));
  }
  for (const name of ["parseHTMLUnsafe", "parseHTML"]) wrapMethod(Document, name, () => latch("DECLARATIVE_SHADOW_API"));
  if (typeof HTMLSelectElement !== "undefined") wrapMethod(HTMLSelectElement.prototype, "showPicker", (target) => pickerWake({ target }));
  try {
    instrument(document, documentInfo);
    apply(add, document, ["fullscreenchange", () => { documentInfo.dirty = true; scheduleFlush(); }]);
    apply(add, document, ["__bux_sentinel_self_check__", () => { selfAck = true; }]);
  } catch { latch("ROOT_INSTRUMENTATION_FAILED"); }
  try {
    const chromium = typeof navigator !== "undefined" && /(?:Chrome|Chromium)\/(\d+)/.exec(navigator.userAgent);
    if (chromium && Number(chromium[1]) < 133) throw new Error();
    for (const selector of [":modal", ":popover-open", "select:open"]) {
      if (!CSS.supports(`selector(${selector})`)) throw new Error();
      apply(docQuery, document, [selector]);
    }
  } catch { latch("SELECTOR_UNSUPPORTED"); }
  if (document.readyState !== "loading") latch("LATE_INSTALL");
  // Startup captures visible open roots only; coverage completion belongs to
  // the independent privileged traversal. Truncation never certifies CLEAR.
  try {
    const queue = [document], seen = new Set(); let visited = 0;
    while (queue.length && visited < 4096 && !permanent) {
      const root = queue.shift();
      if (seen.has(root)) continue;
      seen.add(root);
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
      for (let el = walker.nextNode(); el && visited < 4096; el = walker.nextNode()) {
        visited++;
        if (el.shadowRoot) { registerRoot(el.shadowRoot, el); queue.push(el.shadowRoot); }
      }
    }
    documentInfo.dirty = true; scheduleFlush();
  } catch { latch("ROOT_INSTRUMENTATION_FAILED"); }
  function onHeartbeat() {
    intact(); selfAck = false;
    try { apply(dispatch, document, [new NativeEvent("__bux_sentinel_self_check__")]); } catch {}
    if (!selfAck) latch("INSTRUMENTATION_LOST");
    for (const info of rootRefs) if (!info.ref.deref()) rootRefs.delete(info);
    if (!permanent) for (const info of infos()) if (info.active) recompute(info);
    pushState(); later(onHeartbeat, 1000);
  }
  later(onHeartbeat, 1000);
  try { apply(dispatch, document, [new Custom(s, { detail: stringify({ v: 1, type: "ready" }) })]); } catch {}
})();
