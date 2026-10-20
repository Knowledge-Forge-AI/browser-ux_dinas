// Independent, deliberately incomplete Web-platform specification model.
// HTML popover.html: manual is outside light-dismiss stacks; beforetoggle runs
// inside the toggle algorithm; fully-active documents are required.
// DOM Standard: closed shadowRoot is null; composed/flat ancestry crosses hosts
// and assigned slots. CSS Position 4: top-layer fixed boxes use the viewport.
// CSSOM View: client metrics exclude borders and classic scrollbar gutters.
// Frozen integration contract v1: MAIN + ISOLATED world model, sentinel bridge,
// privileged chrome.dom/Firefox openOrClosedShadowRoot, root-boundary MutationObservers.
import vm from "node:vm";
import nodeCrypto from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const SENTINEL_REASONS = {
  NONE: "NONE",
  ATTACH_SHADOW_UNAVAILABLE: "ATTACH_SHADOW_UNAVAILABLE",
  ATTACH_SHADOW_REPLACED: "ATTACH_SHADOW_REPLACED",
  ROOT_BUDGET_EXCEEDED: "ROOT_BUDGET_EXCEEDED",
  ROOT_INSTRUMENTATION_FAILED: "ROOT_INSTRUMENTATION_FAILED",
  SELECTOR_UNSUPPORTED: "SELECTOR_UNSUPPORTED",
  WORK_BUDGET_EXCEEDED: "WORK_BUDGET_EXCEEDED",
  LATE_INSTALL: "LATE_INSTALL",
  DECLARATIVE_SHADOW_API: "DECLARATIVE_SHADOW_API",
  CLONABLE_ROOT: "CLONABLE_ROOT",
  FOREIGN_REALM_ROOT: "FOREIGN_REALM_ROOT",
  UNCAPTURED_ROOT: "UNCAPTURED_ROOT",
  INSTRUMENTATION_LOST: "INSTRUMENTATION_LOST",
  COVERAGE_PENDING: "COVERAGE_PENDING",
  HANDSHAKE_MISSING: "HANDSHAKE_MISSING",
  SENTINEL_STALE: "SENTINEL_STALE",
  BRIDGE_INVALID: "BRIDGE_INVALID",
  ROOT_VERIFY_UNAVAILABLE: "ROOT_VERIFY_UNAVAILABLE",
  COVERAGE_BUDGET_EXCEEDED: "COVERAGE_BUDGET_EXCEEDED",
};

export function makeDOM(options = {}) {
  let clock = 0, nextId = 1, inToggle = false, executingProduct = false, executingPage = false;
  const jobs = new Map(), microtasks = [], mutations = [], observers = [];
  let activeWorld = "page", sentinelStopped = false;
  const nativeAttachCalls = [];
  const ledger = [], showLog = [], inspected = [], shadows = [], topLayer = [];
  const queries = [];
  const bridgeMessages = [];
  const walkers = [], heartbeatDeferrals = [], executedJobs = [];
  let heartbeatsPaused = false, pageMutations = 0;
  let lastStateMessage = null, lastQueryMessage = null;

  const queriesLedger = {
    total: 0,
    bySelector: {},
    topLayerSelectors: 0,
    byWorld: { main: 0, isolated: 0, page: 0 }
  };

  const defaults = {
    display: "block", position: "static", visibility: "visible", opacity: "1",
    overflow: "visible", overflowX: "visible", overflowY: "visible", contain: "none",
    transform: "none", translate: "none", rotate: "none", scale: "none",
    filter: "none", perspective: "none", zoom: "1", clipPath: "none", maskImage: "none",
    contentVisibility: "visible", direction: "ltr", colorScheme: "normal",
    borderLeftWidth: "0px", borderRightWidth: "0px", borderTopWidth: "0px",
    borderBottomWidth: "0px", paddingTop: "0px", paddingBottom: "0px",
    backgroundColor: "rgba(0, 0, 0, 0)", pointerEvents: "auto", writingMode: "horizontal-tb",
  };

  const camel = (s) => s.replace(/-([a-z])/g, (_, x) => x.toUpperCase());
  const schedule = (fn, delay = 0) => {
    const id = nextId++;
    const world = activeWorld;
    jobs.set(id, { at: clock + Math.max(1, delay), world, name: fn.name, fn: () => { const previous = activeWorld; activeWorld = world; try { return fn(); } finally { activeWorld = previous; } } });
    return id;
  };
  const notifyMutation = (record) => { if (!executingProduct) pageMutations++; mutations.push(record); };
  const write = (record) => ledger.push({ ...record, product: executingProduct });
  const invoke = (fn) => {
    const previous = executingProduct;
    executingProduct = true;
    try { return fn(); } finally { executingProduct = previous; }
  };
  const enqueueMicrotask = (fn) => {
    const world = activeWorld;
    microtasks.push(() => { const previous = activeWorld; activeWorld = world;
      try { return fn(); } finally { activeWorld = previous; } });
  };

  function recordQuery(world, root, selector) {
    queries.push(selector);
    clock += options.queryCost ?? 0;
    queriesLedger.total++;
    queriesLedger.bySelector[selector] = (queriesLedger.bySelector[selector] || 0) + 1;
    queriesLedger.byWorld[activeWorld] = (queriesLedger.byWorld[activeWorld] || 0) + 1;
    if (selector.includes(":modal") || selector.includes(":popover-open") || selector.includes("select:open")) {
      queriesLedger.topLayerSelectors++;
    }
  }

  function recordBridgeMessage(type, detail) {
    let parsed = null;
    try { parsed = JSON.parse(detail); } catch {}
    const msg = { type, detail, parsed, at: clock };
    bridgeMessages.push(msg);
    if (type === "browser-ux-scrollbars-sentinel-s") {
      if (parsed?.type === "state") lastStateMessage = parsed;
    } else if (type === "browser-ux-scrollbars-sentinel-q") {
      lastQueryMessage = parsed;
    }
  }

  // --- Real Prototype Hierarchy ---

  class EventTarget {
    constructor() {
      this.listeners = new Map();
    }
    addEventListener(type, fn, opts) {
      if (typeof fn !== "function" && typeof fn?.handleEvent !== "function") return;
      const capture = typeof opts === "boolean" ? opts : !!opts?.capture;
      const once = typeof opts === "object" ? !!opts?.once : false;
      const passive = typeof opts === "object" ? !!opts?.passive : false;
      const list = this.listeners.get(type) || [];
      list.push({ fn, capture, once, passive, opts, world: activeWorld });
      this.listeners.set(type, list);
    }
    removeEventListener(type, fn) {
      const list = this.listeners.get(type);
      if (list) {
        this.listeners.set(type, list.filter((x) => x.fn !== fn));
      }
    }
    dispatchEvent(event) {
      if (!event || typeof event.type !== "string") {
        throw new TypeError("Failed to execute 'dispatchEvent': parameter 1 is not of type 'Event'");
      }
      if (event.type === "browser-ux-scrollbars-sentinel-q" || event.type === "browser-ux-scrollbars-sentinel-s") {
        recordBridgeMessage(event.type, event.detail);
        if (options.dropVerifyAck && event.type === "browser-ux-scrollbars-sentinel-q" && lastQueryMessage?.type === "verify") return true;
        if (sentinelStopped && event.type === "browser-ux-scrollbars-sentinel-q") return true;
      }

      // Legacy harness input represents browser-generated pointer/key events.
      if (!(event instanceof Event)) {
        Object.setPrototypeOf(event, Event.prototype);
        event.composed ??= /^(pointer|key|wheel)/.test(event.type);
        event.bubbles ??= event.composed;
      }
      const originalTarget = this;
      function retarget(listener) {
        let target = originalTarget, root = target.getRootNode?.();
        while (root?.host && !root.contains(listener)) { target = root.host; root = target.getRootNode(); }
        return target;
      }
      const deliver = (l, node) => {
        const previous = activeWorld; activeWorld = l.world;
        event.target = retarget(node);
        try { return invoke(() => (typeof l.fn === "function" ? l.fn.call(node, event) : l.fn.handleEvent(event))); }
        finally { activeWorld = previous; }
      };
      event.target = this;
      event.defaultPrevented = false;
      event.propagationStopped = false;
      event.immediatePropagationStopped = false;

      const path = [];
      let curr = this;
      while (curr) {
        path.push(curr);
        if (curr.nodeType === 11) { // ShadowRoot / DocumentFragment
          if (event.composed && curr.host) curr = curr.host;
          else break;
        } else if (curr === document.documentElement) {
          path.push(document);
          path.push(window);
          break;
        } else {
          curr = curr.parentNode;
        }
      }
      event.composedPath = () => [...path];

      // Capture phase: window down to target's parent
      const captureAncestors = path.slice(1).reverse();
      for (const node of captureAncestors) {
        if (event.propagationStopped) break;
        event.currentTarget = node;
        const listeners = [...(node.listeners.get(event.type) || [])];
        for (const l of listeners) {
          if (!l.capture) continue;
          deliver(l, node);
          if (l.once) node.removeEventListener(event.type, l.fn);
          if (event.immediatePropagationStopped) break;
        }
      }

      // Target phase
      if (!event.propagationStopped) {
        event.currentTarget = this;
        const listeners = [...(this.listeners.get(event.type) || [])];
        for (const l of listeners) {
          deliver(l, this);
          if (l.once) this.removeEventListener(event.type, l.fn);
          if (event.immediatePropagationStopped) break;
        }
      }

      // Bubble phase: target's parent up to window
      if (event.bubbles && !event.propagationStopped) {
        const bubbleAncestors = path.slice(1);
        for (const node of bubbleAncestors) {
          if (event.propagationStopped) break;
          event.currentTarget = node;
          const listeners = [...(node.listeners.get(event.type) || [])];
          for (const l of listeners) {
            if (l.capture) continue;
            deliver(l, node);
            if (l.once) node.removeEventListener(event.type, l.fn);
            if (event.immediatePropagationStopped) break;
          }
        }
      }

      event.target = originalTarget;
      if (event.type === "pointerdown" && !event.defaultPrevented) {
        document.activeElement = originalTarget.tabIndex >= 0 || /^(input|button|select|textarea)$/.test(originalTarget.localName) ? originalTarget : document.body;
      }
      return !event.defaultPrevented;
    }
  }

  class Event {
    constructor(type, init = {}) {
      if (typeof type !== "string") throw new TypeError("Event type must be a string");
      this.type = type;
      this.bubbles = !!init.bubbles;
      this.composed = !!init.composed;
      this.cancelable = !!init.cancelable;
      this.target = null;
      this.currentTarget = null;
      this.defaultPrevented = false;
      this.propagationStopped = false;
      this.immediatePropagationStopped = false;
    }
    preventDefault() { if (this.cancelable !== false) this.defaultPrevented = true; }
    stopPropagation() { this.propagationStopped = true; }
    stopImmediatePropagation() {
      this.propagationStopped = true;
      this.immediatePropagationStopped = true;
    }
  }

  class CustomEvent extends Event {
    constructor(type, init = {}) {
      super(type, init);
      this.detail = init.detail;
    }
  }

  class Node extends EventTarget {
    constructor() {
      super();
      this.parentNode = null;
    }
    get parentElement() { return this.parentNode?.nodeType === 1 ? this.parentNode : null; }
    get isConnected() {
      let n = this;
      while (n.parentNode) n = n.parentNode;
      return n === document || (n.host && n.host.isConnected) || false;
    }
    getRootNode() {
      let n = this;
      while (n.parentNode) n = n.parentNode;
      return n;
    }
    contains(node) {
      for (let n = node; n; n = n.parentNode) {
        if (n === this) return true;
      }
      return false;
    }
    compareDocumentPosition(other) {
      if (this.contains(other)) return 20;
      if (other.contains(this)) return 10;
      const all = [document.documentElement, ...descendants(document.documentElement)];
      return all.indexOf(this) < all.indexOf(other) ? 4 : 2;
    }
  }

  class DocumentFragment extends Node {
    constructor() {
      super();
      this.nodeType = 11;
      this.children = [];
    }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { return this.children.at(-1) || null; }
    get childNodes() { return this.children; }
    appendChild(node) {
      if (node.parentNode) node.remove();
      node.parentNode = this;
      this.children.push(node);
      notifyMutation({ type: "childList", target: this, addedNodes: [node], removedNodes: [] });
      return node;
    }
    append(...nodes) { for (const n of nodes) this.appendChild(n); }
    replaceChildren(...nodes) { for (const n of [...this.children]) n.remove(); this.append(...nodes); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    querySelectorAll(selector) {
      recordQuery("fragment", this, selector);
      if (options.unsupportedSelector && selector.includes(options.unsupportedSelector)) {
        throw new Error("SyntaxError: unsupported selector");
      }
      return descendants(this).filter((n) => n.matches(selector));
    }
  }

  class ShadowRoot extends DocumentFragment {
    constructor(host, mode = "open", clonable = false) {
      super();
      this.host = host;
      this.mode = mode;
      this.clonable = clonable;
    }
    get ownerDocument() { return this.host ? this.host.ownerDocument : document; }
    get isConnected() { return !!this.host?.isConnected; }
    elementFromPoint(x, y) { return rootHit(this, x, y); }
    elementsFromPoint(x, y) { const n = rootHit(this, x, y); return n ? [n] : []; }
    setHTMLUnsafe(html) {}
    setHTML(html) {}
  }

  class Style {
    constructor(node) {
      this.node = node;
      this.values = new Map();
      return new Proxy(this, {
        get: (o, k) => k in o ? o[k] : o.values.get(String(k)) || "",
        set: (o, k, v) => { if (k in o) o[k] = v; else o.setProperty(String(k), String(v)); return true; },
      });
    }
    setProperty(key, value, priority = "") {
      this.values.set(key, String(value));
      this.values.set(camel(key), String(value));
      if (this.node.page) write({ node: this.node, property: "style", key, value, priority });
    }
    getPropertyValue(key) { return this.values.get(key) || ""; }
    getPropertyPriority() { return "important"; }
    removeProperty(key) { this.values.delete(key); }
  }

  function nativeAttachShadow(init) {
    nativeAttachCalls.push({ receiver: this, args: Array.from(arguments) });
    if (this._shadow || options.shadowFailure) {
      throw options.shadowFailureError || new Error("InvalidStateError: shadow root already attached");
    }
    if (!init || typeof init !== "object") {
      throw new TypeError("Failed to execute 'attachShadow' on 'Element': 1 argument required, but only 0 present.");
    }
    const mode = init.mode;
    if (mode !== "open" && mode !== "closed") {
      throw new TypeError("Failed to execute 'attachShadow' on 'Element': The provided value is not a valid enum value of type ShadowRootMode.");
    }
    const root = new ShadowRoot(this, mode, !!init.clonable);
    root.delegatesFocus = !!init.delegatesFocus;
    this._shadow = root;
    shadows.push(root);
    return root;
  }

  class Element extends Node {
    constructor(name = "div", page = false) {
      super();
      this.localName = name;
      this.tagName = name.toUpperCase();
      this.nodeType = 1;
      this.page = page;
      this.attrs = new Map();
      this.children = [];
      this.style = new Style(this);
      this.computed = {};
      this.rect = null;
      this.metrics = {};
      this._scrollTop = 0;
      this.isModal = false;
      this.isOpen = false;
      this.assignedSlot = null;
      this.capture = new Set();
      this._shadow = null;
    }
    get ownerDocument() { return document; }
    get firstElementChild() { return this.children[0] || null; }
    get nextElementSibling() {
      const a = this.parentNode?.children || [];
      return a[a.indexOf(this) + 1] || null;
    }
    get childNodes() { return this.children; }
    get firstChild() { return this.firstElementChild; }
    get lastElementChild() { return this.children.at(-1) || null; }
    get shadowRoot() { return this._shadow?.mode === "open" ? this._shadow : null; }
    get popover() { return this.attrs.get("popover") || null; }
    set popover(v) { this.setAttribute("popover", v); }
    get inert() { return this.attrs.has("inert"); }
    set inert(v) { if (v) this.setAttribute("inert", ""); else this.removeAttribute("inert"); }
    get id() { return this.attrs.get("id") || ""; }
    set id(v) { this.setAttribute("id", v); }
    get className() { return this.attrs.get("class") || ""; }
    set className(v) { this.setAttribute("class", v); }
    focus() { document.activeElement = this; }
    get tabIndex() { return Number(this.attrs.get("tabindex") ?? -1); }
    set tabIndex(v) { this.setAttribute("tabindex", String(v)); }

    append(...nodes) { for (const n of nodes) this.appendChild(n); }
    appendChild(node) {
      if (node.parentNode) node.remove();
      node.parentNode = this;
      this.children.push(node);
      if (this.page) write({ node: this, property: "append", child: node });
      notifyMutation({ type: "childList", target: this, addedNodes: [node], removedNodes: [] });
      return node;
    }
    removeChild(node) { node.remove(); return node; }
    remove() {
      if (!this.parentNode) return;
      const parent = this.parentNode;
      parent.children.splice(parent.children.indexOf(this), 1);
      this.parentNode = null;
      if (this.isOpen) this.hidePopover();
      notifyMutation({ type: "childList", target: parent, addedNodes: [], removedNodes: [this] });
    }
    replaceChildren(...nodes) { for (const n of [...this.children]) n.remove(); this.append(...nodes); }
    setAttribute(key, value) {
      this.attrs.set(key, String(value));
      if (this.page) write({ node: this, property: "attribute", key });
      notifyMutation({ type: "attributes", target: this, attributeName: key, addedNodes: [], removedNodes: [] });
    }
    getAttribute(key) { return this.attrs.get(key) ?? null; }
    hasAttribute(key) { return this.attrs.has(key); }
    removeAttribute(key) {
      this.attrs.delete(key);
      notifyMutation({ type: "attributes", target: this, attributeName: key });
    }
    matches(selector) {
      if (options.unsupportedSelector && selector.includes(options.unsupportedSelector)) {
        throw new Error("SyntaxError: unsupported selector");
      }
      return selector.split(",").some((s) => {
        s = s.trim();
        if (s === ":modal") return this.isModal || document.fullscreenElement === this;
        if (s === ":popover-open") return this.isOpen;
        if (s === ":popover-open:not(browser-ux-scrollbar-shell)") return this.isOpen && this.localName !== "browser-ux-scrollbar-shell";
        if (s === "select:open") return this.localName === "select" && !!this.selectOpen;
        if (s === "[inert]") return this.inert;
        if (s === "[popover]") return this.popover !== null;
        if (s === "dialog[open]") return this.localName === "dialog" && this.hasAttribute("open");
        if (s === ":is(:modal, :popover-open, select:open)") {
          return (this.isModal || document.fullscreenElement === this) || this.isOpen || (this.localName === "select" && !!this.selectOpen);
        }
        return s === this.localName;
      });
    }
    closest(selector) { for (let n = this; n; n = n.parentElement) if (n.matches(selector)) return n; return null; }
    querySelectorAll(selector) {
      recordQuery("element", this, selector);
      if (options.unsupportedSelector && selector.includes(options.unsupportedSelector)) {
        throw new Error("SyntaxError: unsupported selector");
      }
      return descendants(this).filter((n) => n.matches(selector));
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    checkVisibility(config = {}) {
      const c = computed(this);
      if (!this.isConnected || c.display === "none" || c.visibility === "hidden") return false;
      if (config.opacityProperty) for (let n = this; n; n = n.parentElement) if (computed(n).opacity === "0") return false;
      return true;
    }
    get offsetWidth() { return this.metrics.offsetWidth ?? (parseFloat(this.style.width) || 100); }
    get clientWidth() { return this.metrics.clientWidth ?? (this.offsetWidth - (this.style.overflow === "scroll" || this.style.overflowY === "scroll" ? (options.thickness ?? 15) : 0)); }
    get offsetHeight() { return this.metrics.offsetHeight ?? (parseFloat(this.style.height) || 100); }
    get clientHeight() { return this.metrics.clientHeight ?? this.offsetHeight; }
    get scrollHeight() { return this.metrics.scrollHeight ?? this.clientHeight; }
    get scrollWidth() { return this.metrics.scrollWidth ?? this.clientWidth; }
    get clientLeft() { return this.metrics.clientLeft ?? 0; }
    get clientTop() { return this.metrics.clientTop ?? 0; }
    get offsetLeft() { return this.rect?.left ?? 0; }
    get offsetTop() { return this.rect?.top ?? 0; }
    get offsetParent() { return this.parentElement; }
    get scrollTop() { return this._scrollTop; }
    set scrollTop(v) {
      this._scrollTop = Math.max(0, Math.min(Number(v), this.scrollHeight - this.clientHeight));
      if (this.page) write({ node: this, property: "scrollTop", value: this._scrollTop });
    }
    scrollTo(_, y) { this.scrollTop = typeof _ === "object" ? _.top : y; }
    getBoundingClientRect() {
      const relative = !this.page && this.style.position === "absolute" && this.parentNode?.nodeType === 1;
      const parent = relative ? this.parentNode.getBoundingClientRect() : { left: 0, top: 0, width: 100 };
      const left = this.rect?.left ?? ((parseFloat(this.style.left) || 0) + parent.left);
      const top = this.rect?.top ?? ((parseFloat(this.style.top) || 0) + parent.top);
      let width = this.rect?.width ?? (this.style.width === "100%" ? parent.width : (parseFloat(this.style.width) || this.offsetWidth));
      if (!this.page && this.style.left === "-10000px") width *= Number(document.documentElement.computed.zoom || 1);
      const height = this.rect?.height ?? (parseFloat(this.style.height) || this.offsetHeight);
      return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top };
    }
    getClientRects() { return this.checkVisibility() ? [this.getBoundingClientRect()] : []; }
    showPopover() {
      if (inToggle) throw new Error("InvalidStateError: toggle algorithm in progress");
      if (!this.isConnected || !this.popover || document.visibilityState !== "visible") throw new Error("InvalidStateError");
      if (this.isOpen) return;
      toggle(this, "open");
      showLog.push({ at: clock, node: this, pageTop: topLayer.filter((x) => x.page).length });
    }
    hidePopover() {
      if (inToggle) throw new Error("InvalidStateError: toggle algorithm in progress");
      if (this.isOpen) toggle(this, "closed");
    }
    setPointerCapture(id) { this.capture.add(id); }
    hasPointerCapture(id) { return this.capture.has(id); }
    releasePointerCapture(id) {
      this.capture.delete(id);
      this.dispatchEvent(new CustomEvent("lostpointercapture", { detail: { pointerId: id } }));
    }
    setHTMLUnsafe(html) {}
    setHTML(html) {}
    showModal() {
      this.isModal = true;
      this.setAttribute("open", "");
      modal(this, true);
    }
    close() {
      this.isModal = false;
      this.removeAttribute("open");
      modal(this, false);
    }
  }

  Element.prototype.attachShadow = nativeAttachShadow;

  Object.defineProperty(Element.prototype, "openOrClosedShadowRoot", {
    get() {
      if (options.noPrivilegedAccessor) return undefined;
      if (options.firefoxMode || options.enableFirefoxAccessor) {
        return this._shadow || null;
      }
      return undefined;
    },
    configurable: true
  });

  class HTMLElement extends Element {}

  class HTMLSelectElement extends HTMLElement {
    constructor(name = "select", page = false) {
      super(name, page);
      this._selectOpen = false;
    }
    get selectOpen() { return this._selectOpen; }
    set selectOpen(v) { this._selectOpen = !!v; }
    showPicker() {
      this.selectOpen = true;
    }
  }

  class HTMLInputElement extends HTMLElement {
    constructor(name = "input", page = false) {
      super(name, page);
    }
    showPicker() {}
  }

  function descendants(root) {
    const result = [];
    function walk(node) {
      for (const child of node.children) {
        result.push(child);
        walk(child);
      }
    }
    walk(root);
    return result;
  }

  function toggle(node, state) {
    const old = node.isOpen ? "open" : "closed";
    inToggle = true;
    const before = new CustomEvent("beforetoggle", { detail: { oldState: old, newState: state }, bubbles: true });
    before.target = node;
    before.oldState = old; before.newState = state;
    node.dispatchEvent(before);
    inToggle = false;
    node.isOpen = state === "open";
    const i = topLayer.indexOf(node); if (i !== -1) topLayer.splice(i, 1);
    if (node.isOpen) topLayer.push(node);
    schedule(() => {
      const tog = new CustomEvent("toggle", { detail: { oldState: old, newState: state }, bubbles: true });
      tog.target = node;
      tog.oldState = old; tog.newState = state;
      node.dispatchEvent(tog);
    });
  }

  function computed(node) {
    inspected.push({ node, at: clock });
    clock += options.styleCost ?? 0;
    const value = { ...defaults, ...node.computed };
    for (const [key, v] of node.style.values) value[camel(key)] = v;
    if (node.localName === "browser-ux-scrollbar-shell") {
      Object.assign(value, options.userSheet === false ? { paddingTop: "12px", borderTopWidth: "3px", pointerEvents: "auto" } : {
        display: node.isOpen ? "block" : "none", position: "fixed", pointerEvents: "none",
        width: "815px", height: "600px", marginTop: "0px", marginLeft: "0px",
      });
      if (options.hostAttack) Object.assign(value, options.hostAttack);
    }
    value.getPropertyValue = (key) => value[camel(key)] || "";
    return value;
  }

  function rootHit(root, x, y) {
    if (options.routingBlocked) return null;
    if (options.rootPaintable === false && x >= document.documentElement.clientWidth) return null;
    const nodes = descendants(root).reverse();
    return nodes.find((n) => {
      const r = n.getBoundingClientRect();
      return n.style.pointerEvents === "auto" && x >= r.left && x < r.right && y >= r.top && y < r.bottom;
    }) || null;
  }

  class Document extends Node {
    constructor() {
      super();
      this.nodeType = 9;
      this.contentType = "text/html";
      this.visibilityState = "visible";
      this.readyState = options.loadingState || (options.lateInstall ? "complete" : "loading");
      this.fullscreenElement = null;
      this.compatMode = "CSS1Compat";
      this.children = [];
    }
    get isConnected() { return true; }
    get ownerDocument() { return null; }
    createElement(name) {
      let el;
      if (name === "select") el = new HTMLSelectElement(name);
      else if (name === "input") el = new HTMLInputElement(name);
      else el = new HTMLElement(name);

      if (name === "browser-ux-scrollbar-shell" && !executingPage) {
        // Isolated native attachShadow bypass for extension host
        el.attachShadow = nativeAttachShadow;
      }
      return el;
    }
    createDocumentFragment() {
      return new DocumentFragment();
    }
    createTreeWalker(root, whatToShow = 1) {
      walkers.push({ root, world: activeWorld, at: clock,
        purpose: new Error().stack.includes("coverageSlice") ? "coverage" : "discovery" });
      let current = root;
      return {
        get currentNode() { return current; },
        nextNode() {
          if (current.children.length) return current = current.children[0];
          while (current !== root) {
            if (current.nextElementSibling) return current = current.nextElementSibling;
            current = current.parentNode;
            if (!current) return null;
          }
          return null;
        }
      };
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    querySelectorAll(selector) {
      recordQuery("document", this, selector);
      if (options.unsupportedSelector && selector.includes(options.unsupportedSelector)) {
        throw new Error("SyntaxError: unsupported selector");
      }
      return [this.documentElement, ...descendants(this.documentElement)].filter((n) => n.matches(selector));
    }
    elementsFromPoint(x, y) {
      if (options.hitTargets) return options.hitTargets(x, y);
      return descendants(this.documentElement).filter((n) => n.page && n.checkVisibility()).reverse().filter((n) => {
        const r = n.getBoundingClientRect(); return x >= r.left && x < r.right && y >= r.top && y < r.bottom;
      });
    }
    elementFromPoint(x, y) {
      return this.elementsFromPoint(x, y)[0] || this.body;
    }
    setHTMLUnsafe(html) {}
    setHTML(html) {}
  }

  Document.parseHTMLUnsafe = function(html) { return new Document(); };
  Document.parseHTML = function(html) { return new Document(); };

  const document = new Document();
  document.documentElement = new Element("html", true);
  document.documentElement.parentNode = document;
  document.children = [document.documentElement];
  document.body = new Element("body", true);
  document.documentElement.appendChild(document.body);
  document.activeElement = document.body;
  Object.assign(document.documentElement.metrics, {
    clientWidth: 800, offsetWidth: 800, clientHeight: 600, offsetHeight: 600,
    scrollHeight: options.rootHeight ?? 1800
  });
  document.scrollingElement = document.documentElement;

  class MutationObserver {
    constructor(fn) { this.fn = fn; this.world = activeWorld; this.targets = []; observers.push(this); }
    observe(target, config) { if (options.instrumentFailure && target.nodeType === 11) throw new Error("instrument failure"); this.targets.push({ target, config }); }
    disconnect() { this.targets = []; }
    takeRecords() { return []; }
  }

  class BoxObserver {
    constructor(fn) { this.fn = fn; this.targets = new Set(); }
    observe(target) {
      this.targets.add(target);
      microtasks.push(() => this.fn([{ target, isIntersecting: true, intersectionRatio: 1, contentRect: target.getBoundingClientRect() }]));
    }
    unobserve(target) { this.targets.delete(target); }
    disconnect() { this.targets.clear(); }
  }

  class Window extends EventTarget {
    constructor() {
      super();
      this.innerWidth = 815;
      this.innerHeight = 600;
      this.visualViewport = null;
      this.document = document;
      this.getComputedStyle = computed;
    }
    scrollTo(x, y) {
      document.scrollingElement.scrollTop = typeof x === "object" ? x.top : y;
    }
  }

  const window = new Window();
  window.window = window;
  window.self = window;

  const chromeApi = {
    runtime: {
      lastError: null,
      sendMessage: (message, callback) => {
        if (options.ack === "throw") throw new Error("context invalidated");
        if (options.ack !== "timeout") microtasks.push(() => callback?.({ ok: options.ack !== false }));
      }
    },
    dom: (options.noPrivilegedAccessor || options.firefoxMode) ? undefined : {
      openOrClosedShadowRoot: (el) => {
        if (!el || el.nodeType !== 1) return null;
        return el._shadow || null;
      }
    }
  };

  const cryptoApi = {
    randomUUID: () => nodeCrypto.randomUUID().replace(/-/g, ""),
    getRandomValues: (buffer) => nodeCrypto.getRandomValues(buffer),
  };

  const perfApi = {
    now: () => clock,
  };

  const cssApi = {
    supports: (query) => {
      if (options.popover === false) return false;
      if (options.unsupportedSelector && query.includes(options.unsupportedSelector)) return false;
      return true;
    }
  };

  // --- MAIN Realm API ---
  const mainApi = {
    window, document,
    EventTarget, Event, CustomEvent,
    Node, NodeFilter: { SHOW_ELEMENT: 1, FILTER_ACCEPT: 1 },
    Document, DocumentFragment, ShadowRoot,
    Element, HTMLElement, HTMLSelectElement, HTMLInputElement,
    MutationObserver,
    CSS: cssApi,
    performance: perfApi,
    crypto: cryptoApi,
    navigator: { userAgent: `Chrome/${options.chromeMajor ?? 149}.0` },
    WeakRef, WeakMap, WeakSet, Reflect,
    queueMicrotask: enqueueMicrotask,
    setTimeout: schedule, clearTimeout: (id) => jobs.delete(id),
    setInterval: (fn, n) => {
      let id;
      const run = () => { fn(); id = schedule(run, n); };
      id = schedule(run, n);
      return id;
    },
    clearInterval: (id) => jobs.delete(id),
  };
  const mainContext = vm.createContext(mainApi);

  // --- ISOLATED Realm API ---
  const isolatedApi = {
    window, document,
    EventTarget, Event, CustomEvent,
    Node, NodeFilter: { SHOW_ELEMENT: 1, FILTER_ACCEPT: 1 },
    Document, DocumentFragment, ShadowRoot,
    Element, HTMLElement, HTMLSelectElement, HTMLInputElement,
    MutationObserver, IntersectionObserver: BoxObserver, ResizeObserver: BoxObserver,
    CSS: cssApi,
    performance: perfApi,
    crypto: cryptoApi,
    navigator: { userAgent: `Chrome/${options.chromeMajor ?? 149}.0` },
    chrome: chromeApi,
    navigator: {
      userAgent: options.userAgent || "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    },
    getComputedStyle: computed,
    requestAnimationFrame: (fn) => schedule(() => fn(perfApi.now()), 16),
    cancelAnimationFrame: (id) => jobs.delete(id),
    requestIdleCallback: (fn) => schedule(() => fn({ timeRemaining: () => 4, didTimeout: false }), 1),
    cancelIdleCallback: (id) => jobs.delete(id),
    queueMicrotask: enqueueMicrotask,
    setTimeout: schedule, clearTimeout: (id) => jobs.delete(id),
    setInterval: (fn, n) => {
      let id;
      const run = () => { fn(); id = schedule(run, n); };
      id = schedule(run, n);
      return id;
    },
    clearInterval: (id) => jobs.delete(id),
    innerWidth: 815, innerHeight: 600,
    WeakRef, WeakMap, WeakSet, Reflect,
  };
  const isolatedContext = vm.createContext(isolatedApi);

  function flush() {
    let loops = 0;
    while (microtasks.length || mutations.length) {
      if (++loops > 1000) throw new Error("unbounded microtask/mutation churn");
      while (microtasks.length) invoke(microtasks.shift());
      const batch = mutations.splice(0);
      for (const ob of observers) {
        const records = batch.filter((r) => ob.targets.some(({ target, config }) => {
          if (r.type === "attributes" && (!config.attributes || (config.attributeFilter && !config.attributeFilter.includes(r.attributeName)))) return false;
          if (r.type === "childList" && !config.childList) return false;
          return target === r.target || (config.subtree && target.getRootNode() === r.target.getRootNode() && target.contains(r.target));
        }));
        if (records.length) { const previous = activeWorld; activeWorld = ob.world; try { invoke(() => ob.fn(records)); } finally { activeWorld = previous; } }
      }
    }
  }

  function advance(ms, maxJobs = 20000) {
    const end = clock + ms;
    let count = 0;
    flush();
    for (;;) {
      const entry = [...jobs].filter(([, x]) => x.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!entry) break;
      if (++count > maxJobs) throw new Error("unbounded scheduled work");
      const [id, job] = entry;
      if (heartbeatsPaused && ["onHeartbeat", "sentinelHeartbeat"].includes(job.name)) {
        heartbeatDeferrals.push({ name: job.name, at: clock }); job.at = end + 1; continue;
      }
      if (sentinelStopped && job.name === "onHeartbeat") { job.at = end + 1; continue; }
      jobs.delete(id);
      clock = Math.max(clock, job.at);
      executedJobs.push({ world: job.world, name: job.name, at: clock });
      invoke(job.fn);
      flush();
    }
    clock = Math.max(clock, end);
    return count;
  }

  function node(parent = document.body, init = {}) {
    const previous = executingPage;
    executingPage = true;
    try {
      const el = document.createElement(init.name || "div");
      el.page = true;
      Object.assign(el.computed, init.computed);
      Object.assign(el.metrics, { offsetWidth: 115, clientWidth: 100, offsetHeight: 180, clientHeight: 180, scrollHeight: 600 }, init.metrics);
      el.rect = init.rect || { left: 100, top: 80, width: el.offsetWidth, height: el.offsetHeight };
      if (!init.computed) el.computed.overflowY = "auto";
      parent.appendChild(el);
      return el;
    } finally {
      executingPage = previous;
    }
  }

  let loadedDir;
  function installMain() {
    if (options.sentinelAbsent) return;
    const previous = activeWorld; activeWorld = "main";
    document.readyState = options.lateInstall ? "complete" : "loading";
    try { vm.runInContext(readFileSync(join(loadedDir, "toplayer-sentinel-main.js"), "utf8"), mainContext, { filename: "toplayer-sentinel-main.js" }); } finally { activeWorld = previous; }
    if (!options.loading) document.readyState = "complete";
    flush();
  }
  function load(dir) {
    loadedDir = dir;
    ledger.length = 0;
    mutations.length = 0;

    // MAIN starts loading by default
    document.readyState = options.loadingState || (options.lateInstall ? "complete" : "loading");

    if (!options.isolatedFirst && !options.sentinelDelay && !options.sentinelAbsent) installMain();
    // Isolated starts complete by default (unless options.loading is explicitly true)
    if (!options.loading) {
      document.readyState = "complete";
    }

    const railCoreCode = readFileSync(join(dir, "rail-core.js"), "utf8");
    const contentCode = readFileSync(join(dir, "content.js"), "utf8");

    activeWorld = "isolated";
    vm.runInContext(railCoreCode, isolatedContext, { filename: "rail-core.js" });
    invoke(() => vm.runInContext(contentCode, isolatedContext, { filename: "content.js" }));

    activeWorld = "page";
    if (options.isolatedFirst) installMain();
    if (options.sentinelDelay) schedule(installMain, options.sentinelDelay);
    flush();
  }

  function fullscreen(el) {
    document.fullscreenElement = el;
    if (el && options.fullscreenCloses) for (const h of [...topLayer]) if (!h.page) { h.isOpen = false; topLayer.splice(topLayer.indexOf(h), 1); schedule(() => h.dispatchEvent(Object.assign(new Event("toggle"), {newState:"closed"}))); }
    document.dispatchEvent(new CustomEvent("fullscreenchange"));
  }

  function modal(el, open, config = {}) {
    el.isModal = open;
    if (open) {
      el.setAttribute("open", "");
      topLayer.push(el);
    } else {
      el.removeAttribute("open");
      const i = topLayer.indexOf(el);
      if (i >= 0) topLayer.splice(i, 1);
    }
    const before = new CustomEvent("beforetoggle", { detail: { oldState: open ? "closed" : "open", newState: open ? "open" : "closed" }, bubbles: true });
    before.target = el;
    before.oldState = open ? "closed" : "open";
    before.newState = open ? "open" : "closed";
    if (config.events !== false) el.dispatchEvent(before);
    if (config.events !== false) schedule(() => {
      const tog = new CustomEvent("toggle", { detail: { newState: open ? "open" : "closed" }, bubbles: true });
      tog.target = el;
      tog.newState = open ? "open" : "closed";
      el.dispatchEvent(tog);
    });
  }

  function host() { return document.querySelector("browser-ux-scrollbar-shell"); }
  function railNodes() { return shadows.filter((s) => s.host === host()).flatMap((s) => s.children).filter((n) => n.style.pointerEvents === "auto"); }

  return {
    api: isolatedApi,
    nativeAttachCalls,
    nativeRoot: (host, mode = "closed") => nativeAttachShadow.call(host, {mode}),
    declarativePopover: (el, open) => toggle(el, open ? "open" : "closed"),
    installMain,
    stopSentinel: () => { sentinelStopped = true; for (const [id, job] of jobs) if (job.world === "main") jobs.delete(id); },
    replaceAttach: () => { Element.prototype.attachShadow = nativeAttachShadow; },
    notifyMutation,
    // Fault isolation, not browser delivery: document registrations only.
    // Synthetic document batches must not reach unrelated shadow observers.
    notifyWorld: (world, records) => {
      const previous = activeWorld; activeWorld = world;
      try { for (const ob of observers.filter((ob) => ob.world === world && ob.targets.some(({target}) => target === document))) invoke(() => ob.fn(records)); }
      finally { activeWorld = previous; }
      flush();
    },
    // One synthetic delivery cycle for selected root registrations. This
    // isolates the ISOLATED aggregate budget from MAIN's shared record budget.
    notifyRootBatch: (world, batches) => {
      const previous = activeWorld; activeWorld = world;
      try {
        for (const {root, records} of batches) {
          for (const ob of observers.filter(ob => ob.world === world && ob.targets.some(({target}) => target === root))) invoke(() => ob.fn(records));
        }
      } finally { activeWorld = previous; }
      flush();
    },
    pauseHeartbeats: () => { heartbeatsPaused = true; },
    resumeHeartbeats: () => { heartbeatsPaused = false; },
    pauseBridge: () => { sentinelStopped = true; },
    resumeBridge: () => { sentinelStopped = false; },
    walkers, heartbeatDeferrals, executedJobs,
    get pageMutations() { return pageMutations; },
    clearDocumentListeners: () => document.listeners.clear(),
    mainApi,
    isolatedApi,
    mainContext,
    isolatedContext,
    context: isolatedContext,
    document,
    window,
    ledger,
    showLog,
    inspected,
    topLayer,
    shadows,
    jobs,
    queries,
    queriesLedger,
    bridgeMessages,
    get lastStateMessage() { return lastStateMessage; },
    get lastQueryMessage() { return lastQueryMessage; },
    get sentinelState() { return lastStateMessage?.state || "UNKNOWN"; },
    get sentinelReason() { return lastStateMessage?.reason || "HANDSHAKE_MISSING"; },
    get sentinelBound() { return !!lastStateMessage?.bound; },
    get sentinelEpoch() { return lastStateMessage?.epoch ?? 0; },
    node,
    pageElement: (name) => { const el = document.createElement(name); el.page = true; return el; },
    load,
    advance,
    flush,
    fullscreen,
    modal,
    host,
    railNodes,
    now: () => clock,
    topLayerQueriesCount: () => queriesLedger.topLayerSelectors,

    // Bridge testing helpers via actual native CustomEvents
    sendCorruptedState: (override) => {
      const msg = {
        v: 1, type: "state",
        session: lastQueryMessage?.session || "0123456789abcdef0123456789abcdef",
        instance: "badinstance0123456789abcdef0123",
        seq: 9999, epoch: lastStateMessage?.epoch || 0,
        state: "CLEAR", reason: "NONE", bound: true, reply: 0,
        ...override
      };
      document.dispatchEvent(new CustomEvent("browser-ux-scrollbars-sentinel-s", { detail: JSON.stringify(msg) }));
    },
    sendOutOfSequenceState: () => {
      const msg = {
        v: 1, type: "state",
        session: lastQueryMessage?.session || "0123456789abcdef0123456789abcdef",
        instance: lastStateMessage?.instance || "0123456789abcdef0123456789abcdef",
        seq: 1, epoch: lastStateMessage?.epoch || 0,
        state: "CLEAR", reason: "NONE", bound: true, reply: 0
      };
      document.dispatchEvent(new CustomEvent("browser-ux-scrollbars-sentinel-s", { detail: JSON.stringify(msg) }));
    },
    dispatchMalformedBridgeMessage: () => {
      document.dispatchEvent(new CustomEvent("browser-ux-scrollbars-sentinel-s", { detail: "not-valid-json{" }));
    },
  };
}
