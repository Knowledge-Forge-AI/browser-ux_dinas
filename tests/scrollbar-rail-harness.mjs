// Observable invariants against the real content adapter and independent DOM
// model. No oracle calls the product's core for its expected answer.
import { makeDOM } from "./scrollbar-rail-fakedom.mjs";
const dir = process.argv[2], selected = process.argv[3];
const require = (condition, message) => { if (!condition) throw new Error(message); };
const tests = {};
const run = (options = {}, setup) => {
  const d = makeDOM(options); setup?.(d); d.load(dir); d.advance(1000); return d;
};
const boxAt = (d, x) => d.railNodes().find((b) => Math.abs(b.getBoundingClientRect().left - x) < .1);
const pointer = (node, type, x, y, extra = {}) => node.dispatchEvent({ type, clientX: x, clientY: y, pointerId: 9, button: 0, ...extra });
function safe(d) {
  require(d.showLog.filter((s) => !s.node.page).every((s) => s.pageTop === 0), "host shown over intentional page top layer");
  require(d.railNodes().length <= 24, "rail bound exceeded");
  for (const entry of d.ledger.filter((entry) => entry.product)) {
    require(entry.property === "scrollTop" || (entry.property === "append" && entry.child.localName === "browser-ux-scrollbar-shell"), "page presentation was mutated");
  }
}
tests.activation = () => {
  for (const options of [{ popover: false }, { ack: false }, { ack: "timeout" }, { ack: "throw" }]) {
    const d = run(options); d.advance(6000); require(!d.host(), "host must wait for capability and confirmed USER sheet");
  }
  const d = makeDOM({ loading: true }); d.load(dir); d.advance(1000);
  require(!d.host(), "host inserted before parser complete");
  d.document.readyState = "complete"; d.document.dispatchEvent({ type: "DOMContentLoaded" }); d.advance(1000);
  require(d.host()?.isOpen, "parser completion did not activate");
  require(d.document.documentElement.lastElementChild === d.host(), "host not appended after parser");
  require(d.host().shadowRoot === null && d.shadows.length === 1, "shadow not closed or not singular"); safe(d);
};
tests.empty = () => {
  const d = run({ rootHeight: 600 }); require(!d.host(), "non-scroll document created a host"); safe(d);
};
tests.geometry = () => {
  const d = run({}, (d) => d.node());
  const root = boxAt(d, 800), nested = boxAt(d, 200);
  require(root && nested, "normal root/nested rails absent");
  require(root.getBoundingClientRect().width === 15 && root.getBoundingClientRect().height === 600, "root strip misplaced");
  const r = nested.getBoundingClientRect();
  require(r.width === 15 && r.top === 80 && r.height === 180, "nested strip not in its own gutter");
  for (const b of d.railNodes()) require(b.style.pointerEvents === "auto", "track not pointer active");
  require(d.api.getComputedStyle(d.host()).pointerEvents === "none", "shell intercepts page input"); safe(d);
};
tests.rootStyles = () => {
  for (const computed of [{ transform: "matrix(1, 0, 0, 1, 10, 20)" }, { maskImage: "linear-gradient(black, transparent)" },
    { clipPath: "inset(0 15px 0 0)" }, { opacity: ".3", filter: "blur(1px)" }]) {
    const d = run({}, (d) => Object.assign(d.document.documentElement.computed, computed));
    require(boxAt(d, 800), "root CSS leaked into viewport placement"); safe(d);
  }
};
tests.rootOverflow = () => {
  for (const prop of ["hidden", "clip"]) {
    for (const where of ["html", "body"]) {
      const d = run({}, (d) => { const el = where === "html" ? d.document.documentElement : d.document.body; el.computed.overflowY = prop; });
      require(!d.railNodes().length, `${where} ${prop} became scrollable`); safe(d);
    }
  }
};
tests.rootPaintVariable = () => {
  const d = run({ rootPaintable: false });
  require(!boxAt(d, 800), "unpaintable gutter silently retained a decorative rail");
  require(!d.ledger.some((x) => x.property === "style"), "unpaintable gutter altered native behavior"); safe(d);
};
tests.nonFocusable = () => {
  const d = run({}, (d) => d.node());
  const extensionNodes = [d.host(), ...d.shadows.flatMap((s) => s.children.flatMap((box) => [box, ...box.children, ...box.children.flatMap((track) => track.children)]))];
  require(extensionNodes.every((n) => !n.hasAttribute("tabindex")), "extension added click/programmatic focusability"); safe(d);
};
tests.routingRecovery = () => {
  const options = {};
  const d = run(options, (d) => d.node());
  options.routingBlocked = true; d.advance(900);
  require(!d.host().isOpen && !d.railNodes().length, "ambiguous routing failure retained an active shell");
  options.routingBlocked = false; d.advance(1200);
  require(d.host().isOpen && boxAt(d, 800), "routing recovery incorrectly latched root-gutter failure"); safe(d);
};
tests.selectRecovery = () => {
  const d = run(); const picker = d.node(d.document.body, { name: "select" });
  picker.selectOpen = true; d.advance(1200); require(!d.host().isOpen, "open select not suspended");
  picker.selectOpen = false; d.advance(1200); require(d.host().isOpen, "select close without event never recovered"); safe(d);
};
tests.dynamicRootZoom = () => {
  const d = run(); d.document.documentElement.computed.zoom = "1.5";
  d.window.dispatchEvent({ type: "resize" }); d.advance(100);
  require(!d.host().isOpen && !d.railNodes().length, "late ancestor zoom left misplaced rails active"); safe(d);
};
tests.layoutBudgetRetention = () => {
  const options = { rootHeight: 600 };
  const d = run(options, (d) => { for (let i = 0; i < 8; i++) d.node(d.document.body, { rect: { left: 50 * i, top: 80, width: 115, height: 180 } }); });
  const before = d.railNodes(); require(before.length === 8, "setup lacks active rails");
  options.styleCost = .5; d.window.dispatchEvent({ type: "resize" }); d.advance(50);
  require(before.every((box) => box.isConnected), "time-slice discarded unvisited active rails"); safe(d);
};
tests.opacityEligibility = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    const parent = d.node(d.document.body, { computed: { opacity: "0" } }); d.node(parent);
  });
  require(!d.railNodes().length, "invisible opacity-zero scroller got an exposed rail"); safe(d);
};
tests.dragQueryBound = () => {
  const d = run(); const thumb = boxAt(d, 800).children[0].children[0];
  pointer(thumb, "pointerdown", 807, 20); const queries = d.queries.length;
  for (let i = 0; i < 50; i++) pointer(thumb, "pointermove", 807, 20 + i);
  require(d.queries.length === queries, "drag movement performs whole-document selectors");
  require(d.document.scrollingElement.scrollTop > 0, "query bound disabled actual dragging"); safe(d);
};
tests.selectorCostBackoff = () => {
  const d = run({queryCost: 20}); const count = d.queries.length;
  d.advance(10000);
  require(!d.host()?.isOpen && d.queries.length - count < 12, "expensive top-layer selectors bypassed refusal backoff"); safe(d);
};
tests.hostCascade = () => {
  for (const options of [{ userSheet: false }, { hostAttack: { opacity: "0" } }, { hostAttack: { maskImage: "none-invalid" } },
    { hostAttack: { paddingTop: "20px" } }]) {
    const d = run(options); require(!d.host()?.isOpen && !d.railNodes().length, "contested cascade left rails open"); safe(d);
  }
};
tests.thickness = () => {
  for (const thickness of [0, 5, 33]) {
    const d = run({ thickness }); require(!d.host()?.isOpen, "unsupported thickness invented a fallback"); safe(d);
  }
};
tests.preexistingTopLayer = () => {
  for (const kind of ["modal", "manual", "auto"]) {
    const d = run({}, (d) => {
      const e = d.node(d.document.body, { name: kind === "modal" ? "dialog" : "div" });
      if (kind === "modal") d.modal(e, true); else { e.popover = kind; e.showPopover(); }
    });
    require(!d.host()?.isOpen && !d.railNodes().length, `preexisting ${kind} bypassed`); safe(d);
  }
};
tests.topLayerLifecycle = () => {
  for (const kind of ["modal", "manual", "auto"]) {
    const d = run(); const e = d.node(d.document.body, { name: kind === "modal" ? "dialog" : "div" });
    if (kind === "modal") d.modal(e, true); else { e.popover = kind; e.showPopover(); }
    d.flush(); require(!d.host()?.isOpen, `${kind} failed prompt suspension`);
    if (kind === "modal") d.modal(e, false); else e.hidePopover();
    d.flush(); d.advance(100); require(!d.host()?.isOpen, "resume fought exit transition");
    d.advance(1000); require(d.host()?.isOpen, "normal recovery failed"); safe(d);
  }
};
tests.manualStack = () => {
  const d = run(); const a = d.node(), b = d.node(); a.popover = "manual"; b.popover = "auto";
  a.showPopover(); b.showPopover(); d.advance(1000);
  require(a.isOpen && b.isOpen, "extension closed/reordered page popover stack");
  require(d.topLayer.indexOf(a) < d.topLayer.indexOf(b), "page stack reordered");
  b.hidePopover(); d.advance(1000); require(!d.host()?.isOpen, "persistent manual toast bypassed");
  a.hidePopover(); d.advance(1000); require(d.host()?.isOpen, "manual toast close did not recover");
  const shows = d.showLog.length; d.document.dispatchEvent({ type: "keydown", key: "Escape" }); d.document.dispatchEvent({ type: "pointerdown" }); d.advance(1000);
  require(d.host().isOpen && d.showLog.length === shows, "extension joined light-dismiss stack"); safe(d);
};
tests.shadowTopLayer = () => {
  const d = run({}, (d) => {
    const parent = d.node(); parent.metrics.scrollHeight = parent.clientHeight;
    const root = parent.attachShadow({ mode: "open" });
    const dialog = d.node(root, { name: "dialog" }); dialog.isModal = true;
    d.shadowDialog = dialog;
  });
  require(!d.host()?.isOpen, "known open-shadow modal bypassed");
  d.modal(d.shadowDialog, false); d.advance(1000); require(d.host()?.isOpen, "shadow modal recovery failed");
  d.modal(d.shadowDialog, true); d.flush(); require(!d.host()?.isOpen, "noncomposed shadow toggle lacked listener"); safe(d);
};
tests.fullscreenVariants = () => {
  for (const fullscreenCloses of [false, true]) {
    const d = run({ fullscreenCloses }); const target = d.node();
    for (let i = 0; i < 4; i++) {
      d.fullscreen(target); d.flush(); require(!d.host()?.isOpen, "fullscreen did not suspend");
      d.fullscreen(null); d.advance(1000); require(d.host()?.isOpen, "expected engine close counted as contest");
    }
    safe(d);
  }
};
tests.documentLifecycle = () => {
  const d = run();
  for (let i = 0; i < 4; i++) {
    d.window.dispatchEvent({ type: "pagehide" }); d.advance(100); require(!d.host()?.isOpen, "inactive document shown");
    d.window.dispatchEvent({ type: "pageshow" }); d.advance(1000); require(d.host()?.isOpen, "bfcache return counted as contest");
  }
  d.document.visibilityState = "hidden"; d.document.dispatchEvent({ type: "visibilitychange" }); d.advance(1000);
  require(!d.host()?.isOpen, "hidden document shown"); safe(d);
};
tests.dragAndSuspend = () => {
  const d = run(); const b = boxAt(d, 800), thumb = b.children[0].children[0];
  pointer(thumb, "pointerdown", 808, 20); require(thumb.hasPointerCapture(9), "no capture");
  pointer(thumb, "pointermove", 808, 120);
  require(d.document.scrollingElement.scrollTop === 300, "drag mapping is not range/travel");
  const modal = d.node(d.document.body, { name: "dialog" }); d.modal(modal, true); d.flush();
  require(!thumb.hasPointerCapture(9), "suspension retained capture");
  const top = d.document.scrollingElement.scrollTop;
  pointer(thumb, "pointermove", 808, 220); require(d.document.scrollingElement.scrollTop === top, "suspended drag leaked"); safe(d);
};
tests.trackAndWheel = () => {
  const d = run(); const b = boxAt(d, 800), track = b.children[0];
  pointer(track, "pointerdown", 808, 400); require(d.document.scrollingElement.scrollTop === 525, "track did not take one .875-page step");
  for (const [mode, delta, expected] of [[0, 5, 530], [1, 2, 562], [2, .5, 862]]) {
    const event = { type: "wheel", clientX: 808, clientY: 300, deltaMode: mode, deltaY: delta };
    b.dispatchEvent(event); require(d.document.scrollingElement.scrollTop === expected && event.defaultPrevented, "wheel normalization/routing wrong");
  }
  d.document.dispatchEvent({ type: "wheel", target: d.document.body, deltaMode: 0, deltaY: 10 });
  require(d.document.scrollingElement.scrollTop === 862, "outside wheel no longer page owned"); safe(d);
};
tests.eligibility = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    for (const overflowY of ["hidden", "clip", "visible"]) d.node(d.document.body, { computed: { overflowY } });
    d.node(d.document.body, { metrics: { scrollHeight: 180 } });
    const inert = d.node(); inert.setAttribute("inert", "");
    d.node(d.document.body, { rect: { left: -200, top: 0, width: 115, height: 180 } });
    d.node(d.document.body, { computed: { overflowY: "auto", clipPath: "inset(100%)" } });
    d.node(d.document.body, { computed: { overflowY: "auto", transform: "matrix(-1, 0, 0, -1, 0, 0)" } });
    d.node(d.document.body, { metrics: { offsetWidth: 100, clientWidth: 100 } });
  });
  require(!d.railNodes().length, "ineligible target received rail"); safe(d);
};
tests.flatInert = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    const parent = d.node(); parent.metrics.scrollHeight = parent.clientHeight;
    const root = parent.attachShadow({ mode: "open" }); const wrapper = d.node(root); wrapper.setAttribute("inert", "");
    const slot = d.node(wrapper, { name: "slot" }); const child = d.node(parent); child.assignedSlot = slot;
  });
  require(!d.railNodes().length, "inert lost at slot/shadow boundary"); safe(d);
};
tests.layoutClip = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    const wrapper = d.node(d.document.body, { computed: { overflowY: "hidden", overflowX: "hidden" },
      rect: { left: 0, top: 0, width: 50, height: 50 }, metrics: { clientWidth: 50, offsetWidth: 50, clientHeight: 50, offsetHeight: 50 } });
    d.node(wrapper);
    d.fixed = d.node(wrapper, { computed: { overflowY: "auto", position: "fixed" }, rect: { left: 300, top: 80, width: 115, height: 180 } });
  });
  require(d.railNodes().length === 1 && boxAt(d, 400), "fixed escape or fully-clipped exclusion incorrect"); safe(d);
};
tests.clippedTrack = () => {
  const d = run({ rootHeight: 600 }, (d) => d.target = d.node(d.document.body, { rect: { left: 100, top: -100, width: 115, height: 180 } }));
  const b = boxAt(d, 200); require(b && b.getBoundingClientRect().top === 0 && b.getBoundingClientRect().height === 80, "visible track not clipped");
  pointer(b.children[0], "pointerdown", 208, 70);
  require(d.target.scrollTop === 158, "clipped track lost full-band click coordinate"); safe(d);
};
tests.overlap = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    d.parent = d.node(); d.child = d.node(d.parent, { computed: { overflowY: "auto", position: "fixed" }, rect: { left: 100, top: 80, width: 115, height: 180 } });
  });
  const b = d.railNodes().sort((a, b) => Number(b.style.zIndex) - Number(a.style.zIndex))[0];
  b.dispatchEvent({ type: "wheel", clientX: 208, clientY: 100, deltaY: 40, deltaMode: 0 });
  require(d.child.scrollTop === 40 && d.parent.scrollTop === 0, "parent stole overlapping child input"); safe(d);
};
tests.siblingOverlap = () => {
  const options = { rootHeight: 600 }; const d = makeDOM(options);
  const a = d.node(), b = d.node(); options.hitTargets = () => [b, a];
  d.load(dir); d.advance(1000);
  // Send to either extension box; covered sibling must never receive the input.
  const rail = d.railNodes()[0]; rail.dispatchEvent({ type: "wheel", clientX: 208, clientY: 100, deltaY: 40, deltaMode: 0 });
  require(b.scrollTop === 40 && a.scrollTop === 0, "covered sibling received input"); safe(d);
};
tests.discovery = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    for (let i = 0; i < 3000; i++) d.node(d.document.body, { computed: { overflowY: "visible" } });
    d.narrow = d.node(d.document.body, { rect: { left: 10, top: 30, width: 21, height: 180 }, metrics: { offsetWidth: 21, clientWidth: 6 } });
  });
  d.advance(3000); require(boxAt(d, 16), "progressive scan systematically missed narrow late scroller"); safe(d);
};
tests.dynamics = () => {
  const d = run({ rootHeight: 600 }); d.target = d.node(); d.flush(); d.advance(2000);
  require(boxAt(d, 200), "new subtree was not admitted");
  d.target.metrics.scrollHeight = 180; d.advance(1500); require(!d.railNodes().length, "shrink retained rail");
  d.target.metrics.scrollHeight = 600; d.document.dispatchEvent({ type: "scroll", target: d.target }); d.advance(1000);
  require(boxAt(d, 200), "capture scroll did not admit/update");
  d.target.remove(); d.flush(); d.advance(1000); require(!d.railNodes().length, "removed target retained rail"); safe(d);
};
tests.bounds = () => {
  const d = run({}, (d) => { for (let i = 0; i < 280; i++) d.node(); });
  require(d.railNodes().length <= 24, "visible cap exceeded");
  const count = d.advance(60000); require(count < 2000, "candidate saturation caused CPU churn"); safe(d);
};
tests.scanLimit = () => {
  const d = run({}, (d) => { for (let i = 0; i < 61000; i++) d.node(d.document.body, { computed: { overflowY: "visible" } }); });
  const count = d.advance(10000);
  require(d.inspected.length < 60500 && count < 1000, "epoch limit failed");
  const prior = d.inspected.length; d.advance(10000);
  require(d.inspected.length - prior < 1000, "LIMITED document repeatedly rescanned"); safe(d);
};
tests.slowRefusal = () => {
  const d = run({ styleCost: 20 }); const count = d.advance(1000);
  require(!d.host()?.isOpen && count < 100, "pathological cost did not back off"); safe(d);
};
tests.frameworkRemoval = () => {
  const d = run(); const old = d.host(); old.remove(); d.flush(); d.advance(500);
  require(!d.host(), "removed framework host reinserted without backoff");
  d.advance(2000); require(d.host()?.isOpen && d.host() !== old, "bounded detached recovery failed"); safe(d);
};

tests.rootSidesAndQuirks = () => {
  const left = run({}, (d) => d.document.documentElement.metrics.clientLeft = 15);
  require(boxAt(left, 0), "left native root strip was guessed from direction"); safe(left);
  const quirks = run({ rootHeight: 600 }, (d) => {
    d.document.compatMode = "BackCompat"; d.document.scrollingElement = d.document.body;
    Object.assign(d.document.body.metrics, { clientWidth: 800, offsetWidth: 800, clientHeight: 600, offsetHeight: 600, scrollHeight: 1800 });
    d.document.documentElement.metrics.clientWidth = 700;
  });
  require(boxAt(quirks, 800), "quirks root used the wrong scrolling element"); safe(quirks);
};
tests.resizeAndContent = () => {
  const d = run({ rootHeight: 600 }, (d) => d.target = d.node());
  let b = boxAt(d, 200), thumb = b.children[0].children[0];
  require(parseFloat(thumb.style.height) === 54, "initial thumb ratio wrong");
  d.target.scrollTop = 420; d.document.dispatchEvent({ type: "scroll", target: d.target }); d.advance(100);
  require(parseFloat(thumb.style.top) === 126, "ordinary page scroll did not update thumb");
  d.target.metrics.clientHeight = 120; d.target.metrics.offsetHeight = 120; d.target.rect.height = 120;
  d.window.dispatchEvent({ type: "resize" }); d.advance(100);
  b = boxAt(d, 200); require(b.getBoundingClientRect().height === 120 && parseFloat(b.children[0].children[0].style.height) === 24, "resize geometry/thumb wrong");
  d.target.metrics.scrollHeight = 100000; d.window.dispatchEvent({ type: "resize" }); d.advance(100);
  require(parseFloat(b.children[0].children[0].style.height) === 20, "minimum thumb hit target missing"); safe(d);
};
tests.mutationStorm = () => {
  const d = run(); let callbacks = 0;
  for (let batch = 0; batch < 10; batch++) {
    for (let i = 0; i < 1000; i++) d.node(d.document.body, { computed: { overflowY: "visible" } });
    d.flush(); callbacks += d.advance(16);
  }
  callbacks += d.advance(10000);
  require(callbacks < 500 && d.inspected.length < 5000, "mutation storm bypassed queue/throttle bounds"); safe(d);
};
tests.externalContest = () => {
  const d = run();
  for (const delay of [1200,31000,31000]) { d.host().hidePopover(); d.flush(); d.advance(delay); }
  require(!d.host()?.isOpen, "third unexpected hide in one minute did not refuse"); safe(d);
};

tests.sameNamePagePopover = () => {
  const d = run(); const e = new d.api.Element("browser-ux-scrollbar-shell", true);
  d.document.documentElement.appendChild(e); e.popover = "manual"; e.showPopover(); d.flush();
  const actual = d.shadows.find((s) => !s.host.page)?.host;
  require(!actual?.isOpen, "page popover with shell name was excluded by selector");
  d.advance(1500); require(!actual?.isOpen, "name exclusion recovered over page popover"); safe(d);
};

tests.idleContentGrowth = () => {
  const d = run({ rootHeight: 600 }, (d) => {
    for (let i = 0; i < 96; i++) d.node(d.document.body, { metrics: { scrollHeight: 180 } });
    d.target = d.node(d.document.body, { metrics: { scrollHeight: 180 }, rect: { left: 300, top: 30, width: 115, height: 180 } });
  });
  d.advance(3000);
  require(!d.host()?.isOpen, "idle document created a rail without overflow");
  const idleInspections = d.inspected.length, idleQueries = d.queries.length;
  require(d.advance(10000) < 30, "idle work exceeded two bounded sentinel heartbeats");
  require(d.inspected.length === idleInspections && d.queries.length === idleQueries, "idle sentinel performed layout or selector work");
  // Image/font loading can grow content without changing DOM or client size.
  d.target.metrics.scrollHeight = 600;
  d.document.dispatchEvent({ type: "load", target: d.target }); d.advance(2500);
  require(boxAt(d, 400), "resource growth missed a candidate outside the first layout batch"); safe(d);
};

// R6 matrix executes the actual MAIN sentinel and ISOLATED runtime in two VMs.
function closed(d, parent = d.document.body, mode = "closed") {
  const host = d.node(parent, {metrics:{scrollHeight:180}});
  return {host, root:host.attachShadow({mode})};
}
const settled = (d) => { d.flush(); d.advance(1000); };
const hidden = (d) => require(!d.host()?.isOpen && !d.railNodes().length, "unsafe active rails");
const clear = (d) => require(d.sentinelState === "CLEAR", `sentinel is ${d.sentinelState}/${d.sentinelReason}`);
const unknown = (d) => { require(d.sentinelState === "UNKNOWN", "coverage failed open"); hidden(d); };
function shadowModal(noEvents = false) {
  const d = run(), {root} = closed(d), dialog = d.node(root, {name:"dialog"}); settled(d); clear(d);
  d.modal(dialog, true, {events:!noEvents}); d.flush();
  require(d.sentinelState === "ACTIVE", "closed modal not ACTIVE"); hidden(d);
  d.modal(dialog, false, {events:!noEvents}); settled(d); clear(d); require(d.host().isOpen, "modal recovery absent"); safe(d);
}
tests.closedShadowModal = () => shadowModal();
tests.closedShadowModalNoToggleEvents = () => shadowModal(true);
tests.closedShadowPopoverDeclarative = () => {
  const d = run(), {root} = closed(d), pop = d.node(root); pop.popover = "manual"; settled(d); clear(d);
  d.declarativePopover(pop, true); d.flush(); require(d.sentinelState === "ACTIVE", "declarative popover missed"); hidden(d);
  d.declarativePopover(pop, false); settled(d); clear(d); require(d.host().isOpen, "popover recovery absent"); safe(d);
};
tests.lateOpenShadow = () => {
  const d = run(); d.advance(3000); const before = d.nativeAttachCalls.length, {root} = closed(d, d.document.body, "open");
  require(d.nativeAttachCalls.length === before + 1 && d.sentinelEpoch > 0, "late root not immediately captured");
  const dialog = d.node(root, {name:"dialog"}); settled(d); d.modal(dialog, true); d.flush(); hidden(d);
  require(d.sentinelState === "ACTIVE", "late open modal missed"); safe(d);
};
tests.nestedClosedShadow = () => {
  const d = run(), outer = closed(d), inner = closed(d, outer.root), pop = d.node(inner.root); pop.popover = "auto";
  settled(d); clear(d); pop.showPopover(); d.flush(); hidden(d); require(d.sentinelState === "ACTIVE", "nested closed popover missed");
  pop.hidePopover(); settled(d); clear(d); safe(d);
};
tests.rootAfterManyMutations = () => {
  const d = run(); for(let b=0;b<3;b++){for(let i=0;i<100;i++)d.node(); settled(d);}
  const {root} = closed(d), dialog = d.node(root,{name:"dialog"}); settled(d); d.modal(dialog,true);d.flush();hidden(d);
  require(d.sentinelState === "ACTIVE", "late root after mutations missed");safe(d);
};
tests.rootBudgetAtLimit = () => {
  const d = run(); for(let i=0;i<256;i++)closed(d); settled(d); clear(d);
  require(d.shadows.filter(r=>r.host.page).length === 256, "limit setup inaccurate"); safe(d);
};
tests.rootBudgetExceeded = () => {
  const d = run(), roots=[]; for(let i=0;i<257;i++)roots.push(closed(d)); settled(d); unknown(d);
  require(d.sentinelReason === "ROOT_BUDGET_EXCEEDED", "wrong budget reason");
  for(const r of roots)r.host.remove(); d.advance(4000); unknown(d);safe(d);
};
tests.attachShadowReplaced = () => {
  const d = run();d.replaceAttach();d.advance(1100);unknown(d);require(d.sentinelReason === "ATTACH_SHADOW_REPLACED", "replacement not latched");
  d.advance(4000);unknown(d);safe(d);
};
tests.attachShadowThrows = () => {
  const error = new Error("native test exception"), options={}; const d=run(options), host=d.node();settled(d);
  options.shadowFailure=true;options.shadowFailureError=error;const count=d.shadows.length;let caught;
  try{host.attachShadow({mode:"closed"});}catch(e){caught=e;}
  require(caught===error && d.shadows.length===count, "native exception changed or false root registered");safe(d);
};
tests.wrapperFidelity = () => {
  const d=run(), host=d.node();let reads=0;const init={get mode(){reads++;return "closed";},delegatesFocus:true};
  const wrapper=d.mainApi.Element.prototype.attachShadow, desc=Object.getOwnPropertyDescriptor(d.mainApi.Element.prototype,"attachShadow");
  const root=wrapper.call(host,init), call=d.nativeAttachCalls.at(-1);
  require(reads===1 && call.receiver===host && call.args[0]===init && root.host===host && root.mode==="closed" && root.delegatesFocus, "wrapper changed native arguments/options");
  require(wrapper.name==="attachShadow" && wrapper.length===1 && desc.writable && desc.configurable && !Object.hasOwn(wrapper,"prototype"), "wrapper descriptor mismatch");
  let constructs=false;try{new wrapper(init);constructs=true;}catch{}require(!constructs,"wrapper became constructor");safe(d);
};
for(const selector of [":modal",":popover-open","select:open"]){
  tests[`selectorUnsupported${selector.replace(/[^a-z]/g,"")}`]=()=>{const d=run({unsupportedSelector:selector});unknown(d);require(d.sentinelReason==="SELECTOR_UNSUPPORTED","selector failure ignored");};
}
tests.rootInstrumentationFailure = () => {
  const options={},d=run(options);options.instrumentFailure=true;closed(d);settled(d);unknown(d);
  require(d.sentinelReason==="ROOT_INSTRUMENTATION_FAILED","root failure ignored");safe(d);
};
tests.hostPopoverAlone = () => {const d=run();require(d.host().isOpen,"host absent");clear(d);d.advance(4000);clear(d);safe(d);};
tests.hostPlusClosedPopover = () => {
  const d=run(),{root}=closed(d),pop=d.node(root);pop.popover="manual";settled(d);require(d.host().isOpen,"host absent before page open");
  pop.showPopover();require(d.sentinelState==="ACTIVE","both-open state not ACTIVE");d.flush();hidden(d);safe(d);
};
tests.lateHandshake = () => {
  for(const options of [{sentinelDelay:2000},{isolatedFirst:true}]){
    const d=makeDOM(options);d.load(dir);if(options.sentinelDelay){d.advance(1900);require(!d.host(),"host opened before handshake");}
    d.advance(3000);clear(d);require(d.host()?.isOpen,"valid late handshake did not recover");safe(d);
  }
};
tests.missingSentinel = () => {const d=run({sentinelAbsent:true});d.advance(5000);require(!d.host(),"missing sentinel failed open");safe(d);};
tests.heartbeatExpiry = () => {const d=run();require(d.host().isOpen,"setup absent");d.stopSentinel();d.advance(3100);hidden(d);safe(d);};
tests.malformedBridge = () => {
  const corruptions=[null,{},"{", "x".repeat(769), JSON.stringify({v:1,type:"state",state:"CLEAR"})];
  for(const detail of corruptions){const d=run();d.document.dispatchEvent(new d.mainApi.CustomEvent("browser-ux-scrollbars-sentinel-s",{detail}));d.flush();hidden(d);safe(d);}
  for(const edit of [{seq:1},{state:"BAD"},{session:"a".repeat(32)},{extra:true},{epoch:-1}]){
    const d=run();d.sendCorruptedState({instance:d.lastStateMessage.instance,seq:d.lastStateMessage.seq+1,...edit});d.flush();hidden(d);safe(d);
  }
};
tests.changedInstance = () => {const d=run();d.sendCorruptedState({instance:"f".repeat(32),seq:d.lastStateMessage.seq+1});d.flush();hidden(d);d.advance(4000);hidden(d);safe(d);};
tests.pointermoveNoQuery = () => {
  const d=run(),thumb=boxAt(d,800).children[0].children[0];pointer(thumb,"pointerdown",807,20);
  const count=d.queries.length;for(let i=0;i<1000;i++){pointer(thumb,"pointermove",807,20+i%100);d.document.dispatchEvent({type:"pointermove",clientX:10,clientY:10});}
  require(d.queries.length===count,"pointermove queried a tree");require(d.document.scrollingElement.scrollTop>0,"drag did not work");safe(d);
};
tests.adoptedUncapturedClosedHost = () => {
  for(const firefoxMode of [false,true]){
    const d=run({firefoxMode}),outer=closed(d),host=d.pageElement("div"),root=d.nativeRoot(host);const pop=d.node(root);pop.popover="manual";
    settled(d);outer.root.appendChild(host);settled(d);unknown(d);require(d.sentinelReason==="UNCAPTURED_ROOT","adopted inner root missed");pop.showPopover();d.flush();unknown(d);safe(d);
  }
};
tests.droppedDiscoveryRecords = () => {
  const d=run();for(let i=0;i<513;i++)d.node();d.flush();unknown(d);d.advance(3000);clear(d);require(d.host()?.isOpen,"513 ordinary additions failed recovery after bounded cooldown");safe(d);
};
tests.droppedDiscoveryAddedNodes = () => {
  const d=run(),nodes=[];for(let i=0;i<513;i++){const n=d.pageElement("div");n.parentNode=d.document.body;d.document.body.children.push(n);nodes.push(n);}
  const missed=nodes.at(-1),root=d.nativeRoot(missed),pop=d.node(root);pop.popover="manual";
  d.notifyMutation({type:"childList",target:d.document.body,addedNodes:nodes,removedNodes:[]});settled(d);unknown(d);pop.showPopover();d.flush();unknown(d);safe(d);
};
tests.lostVerifyAck = () => {const d=run({dropVerifyAck:true});closed(d);settled(d);hidden(d);d.advance(4000);hidden(d);safe(d);};
tests.crossRootPicker = () => {
  const d=run(),{root}=closed(d),select=d.pageElement("select");root.appendChild(select);settled(d);clear(d);
  d.document.body.dispatchEvent({type:"pointerdown"});select.showPicker();d.advance(100);hidden(d);require(d.sentinelState==="ACTIVE","cross-root picker not detected");
  select.selectOpen=false;d.advance(2000);clear(d);require(d.host().isOpen,"picker close failed recovery");safe(d);
};
tests.parserDsdClosedBackstop = () => {
  const d=makeDOM({loading:true});d.load(dir);const host=d.node();d.nativeRoot(host);d.advance(1000);require(!d.host(),"coverage trusted loading parser");
  d.document.readyState="complete";d.document.dispatchEvent({type:"DOMContentLoaded"});d.advance(1000);unknown(d);require(d.sentinelReason==="UNCAPTURED_ROOT","parser closed root missed");safe(d);
};
tests.lateInstall = () => {const d=run({lateInstall:true});unknown(d);require(d.sentinelReason==="LATE_INSTALL","late install not latched");safe(d);};
tests.dsdApiLatch = () => {const d=run();d.node().setHTMLUnsafe("inert fixture input");d.flush();unknown(d);d.advance(3000);unknown(d);safe(d);};
tests.clonableLatch = () => {const d=run();d.node().attachShadow({mode:"closed",clonable:true});settled(d);unknown(d);require(d.sentinelReason==="CLONABLE_ROOT","clone coverage ignored");safe(d);};
tests.documentOpenProbe = () => {const d=run();d.clearDocumentListeners();d.advance(4000);hidden(d);safe(d);};
tests.coverageAccessorUnavailable = () => {const d=run({noPrivilegedAccessor:true});hidden(d);require(!d.host(),"missing coverage accessor failed open");safe(d);};

tests.selectorRecognizedWithoutSemantics = () => {const d=run({chromeMajor:121});unknown(d);require(d.sentinelReason==="SELECTOR_UNSUPPORTED","old recognized selector treated as semantic support");safe(d);};
tests.selectorFailureAfterInstall = () => {const options={},d=run(options);options.unsupportedSelector=":modal";d.node(d.document.body,{name:"dialog"});settled(d);unknown(d);require(d.sentinelReason==="SELECTOR_UNSUPPORTED","runtime query failure ignored");safe(d);};
tests.mutationCallbackBudget = () => {
  const d=run();for(let i=0;i<241;i++){d.node();d.flush();}unknown(d);
  require(d.sentinelReason==="WORK_BUDGET_EXCEEDED","callback budget ignored");d.advance(3000);clear(d);require(d.host()?.isOpen,"callback budget failed recovery after work stopped");safe(d);
};
tests.recomputationBudget = () => {
  const d=run(),{root}=closed(d),pop=d.node(root);pop.popover="manual";settled(d);
  for(let i=0;i<257;i++){d.declarativePopover(pop,true);d.flush();d.declarativePopover(pop,false);d.flush();}
  unknown(d);require(d.sentinelReason==="WORK_BUDGET_EXCEEDED","root recomputation budget ignored");
  d.advance(3000);clear(d);require(d.host()?.isOpen,"root recomputation budget did not recover after work stopped");safe(d);
};
tests.focusPreserved = () => {
  const d=run(),input=d.node(d.document.body,{name:"input",metrics:{scrollHeight:180}});settled(d);input.focus();
  const thumb=boxAt(d,800).children[0].children[0];pointer(thumb,"pointerdown",807,20);pointer(thumb,"pointermove",807,100);pointer(thumb,"pointerup",807,100);
  require(d.document.activeElement===input,"rail input stole page keyboard focus");safe(d);
};
tests.continuouslyChangingSmallMutationDragPreservation = () => {
  const d=run(),b=boxAt(d,800),thumb=b.children[0].children[0];
  pointer(thumb,"pointerdown",808,20);require(thumb.hasPointerCapture(9),"no capture on drag start");
  for(let i=1;i<=8;i++){
    d.node();d.flush();pointer(thumb,"pointermove",808,20+i*10);
    require(thumb.hasPointerCapture(9),"small mutation canceled drag capture");
    require(d.host()?.isOpen,"small mutation hid host during drag");
  }
  pointer(thumb,"pointerup",808,100);require(d.document.scrollingElement.scrollTop>0,"drag did not scroll page");safe(d);
};
tests.largeParserInsertionRecovery = () => {
  const d=makeDOM({loading:true});d.load(dir);for(let i=0;i<600;i++)d.node();
  d.document.readyState="complete";d.document.dispatchEvent({type:"DOMContentLoaded"});d.flush();unknown(d);
  d.advance(3000);clear(d);require(d.host()?.isOpen,"large parser insertion did not recover after cooldown");safe(d);
};
tests.unrelatedKeystrokesWith26ClosedRoots = () => {
  const d=run();for(let i=0;i<28;i++){const {root}=closed(d),select=d.pageElement("select");root.appendChild(select);}
  settled(d);clear(d);require(d.host()?.isOpen,"host not open before keystrokes");const count=d.queries.length;
  for(let i=0;i<10;i++){
    d.document.body.dispatchEvent({type:"keydown",key:"ArrowDown",bubbles:true});
    d.document.body.dispatchEvent({type:"pointerdown",clientX:10,clientY:10,bubbles:true});
  }
  d.flush();clear(d);require(d.host()?.isOpen,"unrelated keystrokes suspended host");
  require(d.queries.length-count<=1,"unrelated keystrokes queried roots");safe(d);
};
tests.relevantTargetedSelectActivation = () => {
  const d=run(),c1=closed(d),select1=d.pageElement("select");c1.root.appendChild(select1);
  const c2=closed(d),select2=d.pageElement("select");c2.root.appendChild(select2);
  settled(d);clear(d);require(d.host()?.isOpen,"host absent before select activation");
  select1.dispatchEvent({type:"pointerdown",bubbles:true});d.flush();hidden(d);
  require(d.sentinelState==="ACTIVE","targeted select activation did not suspend");
  d.advance(100);select1.selectOpen=false;d.advance(2000);clear(d);
  require(d.host()?.isOpen,"targeted select activation did not recover after close");safe(d);
};
tests.coalescedPickerRoots = () => {
  const d=run(),a=closed(d),b=closed(d),first=d.pageElement("select"),second=d.pageElement("select");
  a.root.appendChild(first);b.root.appendChild(second);settled(d);clear(d);
  first.showPicker();first.selectOpen=false;second.showPicker();d.advance(100);
  hidden(d);require(d.sentinelState==="ACTIVE","coalesced activation lost second picker root");
  second.selectOpen=false;d.advance(2000);clear(d);require(d.host()?.isOpen,"coalesced picker close failed recovery");safe(d);
};
tests.incrementalMutationQueryWalkBoundedness = () => {
  const d=run();for(let i=0;i<6;i++)closed(d);settled(d);clear(d);
  const topBefore=d.topLayerQueriesCount(),qBefore=d.queries.length;
  for(let i=0;i<15;i++){const p=d.pageElement("p");d.document.body.appendChild(p);}
  d.flush();clear(d);require(d.topLayerQueriesCount()===topBefore,"arbitrary content updates triggered root top-layer queries");
  require(d.queries.length-qBefore<=15,"structural inspection exceeded added node count");safe(d);
};
tests.activePageModalDuringMutationOverload = () => {
  const d=run(),modal=d.node(d.document.body,{name:"dialog"});d.modal(modal,true);d.flush();hidden(d);
  require(d.sentinelState==="ACTIVE","modal open did not suspend");
  for(let i=0;i<241;i++){d.node();d.flush();}hidden(d);
  require(!d.host()?.isOpen,"mutation overload exposed host over active modal");
  d.advance(3000);hidden(d);require(d.sentinelState==="ACTIVE","modal active state lost after overload cooldown");
  require(!d.host()?.isOpen,"host reopened while modal is still open");
  d.modal(modal,false);settled(d);clear(d);
  require(d.host()?.isOpen,"host did not recover after modal closed following overload");safe(d);
};
// R7: execute the actual isolated adapter. World-only deliveries deliberately
// isolate the local timer defect; they do not claim native observer ordering.
function batch(d, count, parent = d.document.body) {
  const nodes = [];
  for (let i = 0; i < count; i++) {
    const node = d.pageElement("div"); node.parentNode = parent; parent.children.push(node); nodes.push(node);
  }
  return nodes;
}
const record = (d, nodes = [], removedNodes = [], target = d.document.body) => ({type:"childList", target, addedNodes:nodes, removedNodes});
const fullWalks = (d, since) => d.walkers.filter((w) => w.world === "isolated" && w.purpose === "coverage" && w.root === d.document.documentElement && w.at >= since);
function recoveredWithoutMutation(d, trigger) {
  d.pauseHeartbeats(); const at = d.now(); trigger(); d.flush(); hidden(d);
  const mutations = d.pageMutations, walks = fullWalks(d, at).length;
  d.advance(999); hidden(d);
  require(fullWalks(d, at).length === walks, "full walk during cooldown");
  d.advance(650);
  require(d.pageMutations === mutations, "recovery needed a second page mutation");
  require(fullWalks(d, at + 1000).length > 0, "local cooldown did not start a full walk");
  clear(d); require(d.host()?.isOpen, "rails did not recover");
  for (const name of ["onHeartbeat", "sentinelHeartbeat"]) require(d.heartbeatDeferrals.some((x) => x.name === name), "heartbeat pause did not isolate " + name);
  safe(d);
}
tests.isolatedRecordsOverflowRecovery = () => {
  const d = run(); recoveredWithoutMutation(d, () => d.notifyWorld("isolated", Array.from({length:513}, () => record(d))));
};
tests.isolatedAddedNodesOverflowRecovery = () => {
  const d = run(); recoveredWithoutMutation(d, () => d.notifyWorld("isolated", [record(d, batch(d, 513))]));
};
tests.coverageAddedOverflowRecovery = () => {
  const d = run(); recoveredWithoutMutation(d, () => d.notifyWorld("isolated", [record(d,batch(d,300)),record(d,batch(d,300))]));
};
tests.coverageAddedTwoWorldRecovery = () => {
  const d=run(); recoveredWithoutMutation(d,()=>{d.notifyMutation(record(d,batch(d,300)));d.notifyMutation(record(d,batch(d,300)));});
};
tests.coverageWorkBudgetRecovery = () => {
  const d=run({},d=>batch(d,35000));d.pauseHeartbeats();
  closed(d);d.flush();d.advance(40);
  // ROOT_PENDING forces a second full walk in the same work window.
  const at=d.now();closed(d);d.flush();d.advance(40);hidden(d);
  const mutations=d.pageMutations;d.advance(1700);
  require(d.pageMutations===mutations,"work recovery needed another mutation");
  require(fullWalks(d,at+1000).length>0,"work window did not reset into a full retry");
  clear(d);require(d.host()?.isOpen,"work-budget recovery absent");safe(d);
};
tests.coverageStartBudgetRecovery = () => {
  const d=run();recoveredWithoutMutation(d,()=>{for(let i=0;i<65;i++){d.node();d.flush();}});
};
tests.cooldownNoPolling = () => {
  const d=run();d.pauseHeartbeats();const at=d.now();
  d.notifyWorld("isolated",Array.from({length:513},()=>record(d)));
  d.node();d.flush();hidden(d);d.advance(999);hidden(d);
  require(d.executedJobs.filter((j)=>j.world==="isolated"&&j.at>=at&&j.name==="coverageSlice").length<5,"cooldown polled coverage at 1 ms");
  d.advance(650);clear(d);require(d.host()?.isOpen,"cooldown retry absent");safe(d);
};
tests.structuralTreeLimitHold = () => {
  const d=run(),container=d.pageElement("div");batch(d,61000,container);
  d.document.body.appendChild(container);d.flush();d.advance(1200);hidden(d);
  let before=fullWalks(d,0).length;d.advance(10000);hidden(d);
  require(fullWalks(d,0).length===before,"quiet oversized document auto-retried");
  const host=d.host();if(host){host.remove();d.document.documentElement.appendChild(host);d.flush();d.advance(1200);}
  require(fullWalks(d,0).length===before,"extension host unblocked structural hold");
  for(let i=0;i<35;i++){
    d.notifyWorld("isolated",Array.from({length:513},()=>record(d)));
    d.node(container);d.flush();d.advance(1000);hidden(d);
  }
  require(fullWalks(d,0).length-before<=6,"structural mutation storm bypassed backoff");
  const removed=container.children.splice(0,2100);for(const node of removed)node.parentNode=null;
  d.notifyMutation(record(d,[],removed,container));d.flush();before=fullWalks(d,0).length;
  d.advance(32000);clear(d);require(d.host()?.isOpen,"shrunken tree failed bounded recovery");
  require(fullWalks(d,0).length===before+1,"shrink did not produce exactly one full retry");safe(d);
};
tests.permanentLossSurvivesLocalThrottle = () => {
  for(const local of [false,true]){
    const d=run(local?{noPrivilegedAccessor:true}:{});
    if(!local){for(let i=0;i<257;i++)closed(d);settled(d);}
    const at=d.now(),reason=d.sentinelReason;d.pauseHeartbeats();
    d.notifyWorld("isolated",[record(d,batch(d,600))]);d.advance(1500);d.resumeHeartbeats();d.advance(3500);
    unknown(d);require(d.sentinelReason===reason,"local throttle erased permanent reason");
    require(fullWalks(d,at).length===0,"permanent loss started recovery walk");safe(d);
  }
};
tests.activeModalDuringLocalThrottle = () => {
  const d=run(),{root}=closed(d),modal=d.node(root,{name:"dialog"});settled(d);
  d.modal(modal,true);d.flush();d.pauseHeartbeats();
  d.notifyWorld("isolated",[record(d,batch(d,600))]);d.advance(1700);hidden(d);
  require(d.sentinelState==="ACTIVE","local cooldown cleared active modal");
  const at=d.now();d.modal(modal,false);d.flush();d.advance(800);
  clear(d);require(fullWalks(d,at).length>0,"modal close skipped complete coverage");safe(d);
};
tests.throttleDuringBridgeGap = () => {
  for(const absent of [false,true]){
    const d=absent?makeDOM({sentinelDelay:5000}):run();if(absent)d.load(dir);
    else {d.pauseBridge();d.advance(4100);hidden(d);}
    const at=d.now();d.notifyWorld("isolated",[record(d,batch(d,600))]);d.advance(1500);hidden(d);
    require(fullWalks(d,at).length===0,"missing/stale bridge started coverage");
    if(!absent)d.resumeBridge();d.advance(4500);clear(d);require(d.host()?.isOpen,"liveness gap did not restore rails (absent="+absent+")");safe(d);
  }
};
tests.incrementalRestartRetainsUnwalkedDelta = () => {
  for(const inShadow of [false,true]){
    const d=run(),subtree=d.pageElement("div");
    // A captured disconnected root is known to MAIN, but not yet walked by ISOLATED.
    const interior=inShadow?subtree.attachShadow({mode:"closed"}):subtree;
    const nodes=batch(d,10000,interior),missed=nodes.at(-1);
    const root=d.nativeRoot(missed),pop=d.node(root);pop.popover="manual";
    if(inShadow)settled(d);
    d.document.body.appendChild(subtree);d.flush(); // first slices leave the uncaptured root unwalked
    require(d.sentinelReason!=="UNCAPTURED_ROOT","test reached root before interrupt");
    d.node();d.flush();d.advance(1600);
    unknown(d);require(d.sentinelReason==="UNCAPTURED_ROOT","epoch restart discarded unwalked delta");
    pop.showPopover();d.flush();hidden(d);safe(d);
  }
};
tests.disconnectedUnfinishedRootRetry = () => {
  const d=run(),host=d.pageElement("div"),outer=host.attachShadow({mode:"closed"});
  const nodes=batch(d,10000,outer),missed=nodes.at(-1),inner=d.nativeRoot(missed);
  const pop=d.node(inner);pop.popover="manual";settled(d);
  d.document.body.appendChild(host);d.flush();
  require(d.sentinelReason!=="UNCAPTURED_ROOT","test reached root before disconnect");
  host.remove();d.flush();d.advance(100);clear(d);
  d.document.body.appendChild(host);d.flush();d.advance(1500);
  unknown(d);require(d.sentinelReason==="UNCAPTURED_ROOT","reconnected unfinished root was trusted as verified");
  pop.showPopover();d.flush();hidden(d);safe(d);
};
tests.continuousLargeMutationBoundedHold = () => {
  const d=run(),container=d.pageElement("div");batch(d,25000,container);d.document.body.appendChild(container);d.flush();
  const at=d.now();for(let i=0;i<150;i++){d.node(container);d.flush();d.advance(1);hidden(d);}
  require(fullWalks(d,at).length<=65,"continuous full-walk restarts unbounded");
  // Availability residual: a large walk may wait for a quiet period.
  d.advance(2500);clear(d);require(d.host()?.isOpen,"large document did not recover after quiet period");safe(d);
};
// R8: retained verified interiors must lose skip authority while detached.
const rootWalks = (d, root, since = 0) => d.walkers.filter((w) => w.world === "isolated" && w.purpose === "coverage" && w.root === root && w.at >= since);
function verifiedChain(d, levels = 1) {
  const chain = []; let parent = d.document.body;
  for (let i = 0; i < levels; i++) {
    const host = d.pageElement("div"); parent.appendChild(host);
    const root = host.attachShadow({mode:"closed"}); chain.push({host, root}); parent = root;
  }
  settled(d); clear(d); require(d.host()?.isOpen, "verified setup absent");
  return chain;
}
function foreignThreat(d, parent) {
  const host = d.pageElement("div"), root = d.nativeRoot(host), pop = d.node(root);
  pop.popover = "manual"; parent.appendChild(host); return {host, root, pop};
}
function rejectedThreat(d, threat) {
  settled(d); unknown(d); require(d.sentinelReason === "UNCAPTURED_ROOT", "dirty interior skipped: " + d.sentinelReason);
  threat.pop.showPopover(); d.flush(); hidden(d); unknown(d); safe(d);
}
function bothAccessors(test) { for (const firefoxMode of [false, true]) test(run({firefoxMode}), firefoxMode); }
tests.detachedVerifiedRootReattach = () => bothAccessors((d) => {
  const [{host, root}] = verifiedChain(d); host.remove(); d.flush();
  const threat = foreignThreat(d, root); d.flush(); settled(d); clear(d);
  d.document.body.appendChild(host); rejectedThreat(d, threat);
});
tests.detachedBenignReverify = () => bothAccessors((d) => {
  const [{host, root}] = verifiedChain(d); host.remove(); d.flush(); d.node(root); settled(d); clear(d);
  const before = rootWalks(d, root).length; d.document.body.appendChild(host); settled(d);
  require(rootWalks(d, root).length > before, "benign detached interior not reverified");
  clear(d); require(d.host()?.isOpen, "benign recovery absent"); safe(d);
});
tests.detachedMutationUndone = () => bothAccessors((d) => {
  const [{host, root}] = verifiedChain(d); host.remove(); d.flush();
  const node = d.node(root); d.flush(); node.remove(); settled(d);
  const before = rootWalks(d, root).length; d.document.body.appendChild(host); settled(d);
  require(rootWalks(d, root).length > before, "undone mutation retained stale verification"); clear(d); safe(d);
});
tests.detachedCoalescedMutations = () => bothAccessors((d) => {
  const [{host, root}] = verifiedChain(d); host.remove(); d.flush();
  d.node(root); const threat = foreignThreat(d, root); d.flush();
  d.document.body.appendChild(host); rejectedThreat(d, threat);
});
for (const [name, levels] of [["nestedDetachedAncestor",2],["multiLevelDetachedAncestor",4]]) tests[name] = () => bothAccessors((d) => {
  const chain = verifiedChain(d, levels), outer = chain[0], inner = chain.at(-1);
  outer.host.remove(); d.flush(); const threat = foreignThreat(d, inner.root); d.flush();
  const before = chain.map(({root}) => rootWalks(d, root).length);
  d.document.body.appendChild(outer.host); rejectedThreat(d, threat);
  chain.forEach(({root}, i) => require(rootWalks(d, root).length > before[i], "ancestor interior skipped at level " + i));
});
tests.detachedNeverReattached = () => bothAccessors((d) => {
  const [{host, root}] = verifiedChain(d); host.remove(); d.flush(); foreignThreat(d, root); settled(d);
  clear(d); require(d.host()?.isOpen, "unreachable dirty root latched connected page");
  const count = fullWalks(d, 0).length; d.advance(6000); clear(d);
  require(fullWalks(d, 0).length === count, "detached root caused retries"); safe(d);
});
tests.detachReattachNoMutation = () => bothAccessors((d) => {
  const [{host, root}] = verifiedChain(d), before = rootWalks(d, root).length, full = fullWalks(d, 0).length;
  host.remove(); settled(d); d.document.body.appendChild(host); settled(d); clear(d);
  require(rootWalks(d, root).length === before, "unchanged interior unnecessarily rewalked");
  require(fullWalks(d, 0).length === full, "unchanged detach forced global rescan"); safe(d);
});
tests.reattachImmediateTopLayer = () => bothAccessors((d, firefoxMode) => {
  for (const captured of [false,true]) {
    // Independent documents avoid a permanent uncaptured-root latch carrying over.
    const e = captured ? run({firefoxMode}) : d;
    const [{host, root}] = verifiedChain(e); host.remove(); e.flush();
    const threat = captured ? {pop:e.node(root)} : foreignThreat(e, root); threat.pop.popover = "manual"; e.flush();
    e.document.body.appendChild(host); threat.pop.showPopover(); e.flush();
    require(e.sentinelState !== "CLEAR", "reattach activation exposed CLEAR checkpoint");
    hidden(e); e.advance(32); hidden(e); safe(e);
    if (!captured) require(e.sentinelReason === "UNCAPTURED_ROOT", "threat authority not rejected");
    else require(e.sentinelState === "ACTIVE", "captured activation not ACTIVE");
  }
});
tests.dirtyRootMovesConnected = () => bothAccessors((d, firefoxMode) => {
  for (const intoShadow of [false,true]) {
    const e = intoShadow ? run({firefoxMode}) : d;
    const [{host,root}] = verifiedChain(e), destination = intoShadow ? verifiedChain(e)[0].root : e.node(); settled(e);
    host.remove(); e.flush(); const threat = foreignThreat(e,root); e.flush();
    destination.appendChild(host); rejectedThreat(e,threat);
  }
});
tests.detachedRootPermanentLatch = () => bothAccessors((d) => {
  const [{host,root}] = verifiedChain(d); host.remove(); d.flush(); d.node(root); d.flush();
  d.replaceAttach(); d.advance(1100); unknown(d); const reason = d.sentinelReason, full = fullWalks(d,0).length;
  require(reason === "ATTACH_SHADOW_REPLACED", "permanent setup missing");
  d.document.body.appendChild(host); d.advance(3000); unknown(d);
  require(d.sentinelReason === reason && fullWalks(d,0).length === full, "dirty recovery erased permanent loss"); safe(d);
});
tests.throttledDetachedRoot = () => bothAccessors((d, firefoxMode) => {
  for (const benign of [false,true]) {
    const e = benign ? run({firefoxMode}) : d;
    const [{host,root}] = verifiedChain(e); e.pauseHeartbeats(); host.remove(); e.flush();
    const threat = benign ? (e.node(root), null) : foreignThreat(e,root); e.flush();
    const at = e.now(); e.notifyWorld("isolated",Array.from({length:513},()=>record(e)));
    e.document.body.appendChild(host); e.flush(); hidden(e); const mutations = e.pageMutations;
    e.advance(1700); require(e.pageMutations === mutations, "cooldown needed another mutation");
    require(fullWalks(e,at+1000).length > 0, "cooldown walk absent");
    if (benign) { clear(e); require(e.host()?.isOpen, "benign throttle recovery absent"); safe(e); }
    else rejectedThreat(e,threat);
  }
});
tests.structuralHoldDetachedRoot = () => bothAccessors((d) => {
  const [{host,root}] = verifiedChain(d), container = d.pageElement("div"); batch(d,61000,container);
  d.document.body.appendChild(container); d.flush(); d.advance(1200); hidden(d);
  host.remove(); d.flush(); const threat = foreignThreat(d,root); d.flush(); d.document.body.appendChild(host); d.flush();
  d.advance(32000); hidden(d); const full = fullWalks(d,0).length, jobs = d.executedJobs.length;
  d.advance(10000); hidden(d); require(fullWalks(d,0).length === full, "oversized detach hot retry");
  require(d.executedJobs.slice(jobs).filter(j=>j.name === "coverageSlice").length < 5, "oversized coverage polling");
  container.remove(); d.flush(); d.advance(32000); rejectedThreat(d,threat);
});
tests.disconnectedAddedNodeAtCallback = () => bothAccessors((d) => {
  const [{host,root}] = verifiedChain(d); host.remove(); d.flush(); const node = d.node(root); node.remove(); d.flush();
  const before = rootWalks(d,root).length; d.document.body.appendChild(host); settled(d); clear(d);
  require(rootWalks(d,root).length > before, "callback relied on disconnected added node"); safe(d);
});
tests.reattachBeforeDetachedRecordDelivery = () => bothAccessors((d) => {
  const chain = verifiedChain(d,3), outer = chain[0], inner = chain.at(-1);
  const before = chain.map(({root})=>rootWalks(d,root).length);
  outer.host.remove(); const node = d.node(inner.root); node.remove();
  d.document.body.appendChild(outer.host); settled(d); clear(d);
  chain.forEach(({root},i)=>require(rootWalks(d,root).length > before[i], "connected callback retained stale ancestor " + i));
  safe(d);
});
tests.connectedCallbackDetachedThreat = () => bothAccessors((d, firefoxMode) => {
  for (const sameTurn of [false,true]) {
    const e = sameTurn ? run({firefoxMode}) : d;
    const chain = verifiedChain(e,3), outer = chain[0], inner = chain.at(-1);
    outer.host.remove(); if (!sameTurn) e.flush();
    const threat = foreignThreat(e,inner.root); e.document.body.appendChild(outer.host);
    rejectedThreat(e,threat);
  }
});
tests.restartDropsDetachedPendingTask = () => bothAccessors((d) => {
  const [{host,root}] = verifiedChain(d), wrapper = d.pageElement("div"); batch(d,10000,wrapper);
  const threat = foreignThreat(d,wrapper); d.flush(); root.appendChild(wrapper); d.flush();
  require(d.sentinelReason !== "UNCAPTURED_ROOT", "pending task already completed");
  host.remove(); d.flush(); d.advance(1500); clear(d);
  d.document.body.appendChild(host); rejectedThreat(d,threat);
});
tests.throttleClearedDetachedDelta = () => bothAccessors((d) => {
  const [{host,root}] = verifiedChain(d), wrapper = d.pageElement("div"); batch(d,10000,wrapper);
  const threat = foreignThreat(d,wrapper); d.flush(); root.appendChild(wrapper); d.flush();
  require(d.sentinelReason !== "UNCAPTURED_ROOT", "delta already verified");
  d.notifyWorld("isolated",Array.from({length:513},()=>record(d))); host.remove(); d.flush();
  d.advance(1700); clear(d); d.document.body.appendChild(host); rejectedThreat(d,threat);
});
tests.aggregateRootRemovalBudget = () => bothAccessors((d) => {
  const chain = verifiedChain(d,3), nodes = chain.map(({root}) => Array.from({length:200},()=>d.node(root)));
  settled(d); clear(d); d.pauseHeartbeats(); const at = d.now();
  const batches = chain.map(({root}, i) => {
    root.children = root.children.filter(node=>!nodes[i].includes(node));
    nodes[i].forEach(node=>node.parentNode = null);
    return {root, records:nodes[i].map(node=>record(d,[],[node],root))};
  });
  d.notifyRootBatch("isolated",batches); hidden(d);
  const mutations = d.pageMutations, walks = fullWalks(d,at).length;
  d.advance(999); hidden(d); require(fullWalks(d,at).length === walks, "aggregate throttle bypassed cooldown");
  d.advance(650); clear(d); require(d.pageMutations === mutations, "aggregate recovery needed mutation");
  require(fullWalks(d,at+1000).length > 0, "removal records across roots lost shared budget"); safe(d);
});
tests.detachedCapturedRootFullWalk = () => bothAccessors((d) => {
  const [{host,root}] = verifiedChain(d); host.remove(); d.flush();
  const innerHost = d.pageElement("div"); root.appendChild(innerHost);
  // Mutation occurred while connected; only ROOT_PENDING/full-walk replacement
  // protects the detached root when no root-local childList callback is delivered.
  d.flush(); d.document.body.appendChild(host); settled(d); host.remove(); d.flush();
  const inner = innerHost.attachShadow({mode:"closed"}); settled(d); clear(d);
  d.document.body.appendChild(host); settled(d); clear(d);
  require(rootWalks(d,inner).length > 0, "new captured root skipped after detached full walk");
  const threat = foreignThreat(d,inner); rejectedThreat(d,threat);
});
const result = {};
for (const [name, test] of Object.entries(tests)) {
  if (selected && selected !== name) continue;
  try { test(); result[name] = "PASS"; }
  catch (error) { result[name] = `FAIL: ${error.message}`; }
}
process.stdout.write(JSON.stringify(result) + "\n");
if (Object.values(result).some((r) => r !== "PASS")) process.exitCode = 1;
