// Runs the scrollbar extension scripts against a mocked chrome API in a vm
// context without DOM globals and prints the observed API calls as JSON.
// Usage: node browser-preferences-harness.mjs <extension-dir>
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

const dir = process.argv[2];
const source = (name) => readFileSync(join(dir, name), "utf8");

// How a mocked API call returns: a Promise (resolved or rejected), a plain
// value or nothing, or a synchronous throw.
const RETURNS = {
  resolves: () => Promise.resolve(undefined),
  rejects: () => Promise.reject(new Error("frame gone")),
  undefined: () => undefined,
  object: () => ({}),
  throws: () => {
    throw new Error("Extension context invalidated.");
  },
};

function sandbox(calls, { insert = "resolves", send = "resolves" } = {}) {
  const listeners = [];
  const record = (api, mode = "resolves") => (...args) => {
    calls.push({ api, args });
    return RETURNS[mode]();
  };
  const chrome = {
    runtime: {
      id: "self-extension-id",
      onMessage: { addListener: (fn) => listeners.push(fn) },
      sendMessage: record("runtime.sendMessage", send),
    },
    scripting: {
      insertCSS: record("scripting.insertCSS", insert),
      executeScript: record("scripting.executeScript"),
      registerContentScripts: record("scripting.registerContentScripts"),
    },
    tabs: new Proxy({}, { get: (_, key) => record(`tabs.${String(key)}`) }),
  };
  // No document/window: any DOM access throws a ReferenceError.
  return { context: vm.createContext({ chrome }), listeners };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

// Runs fn and reports calls, synchronous errors and unhandled rejections.
async function observe(options, fn) {
  const calls = [];
  const { context, listeners } = sandbox(calls, options);
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(String(reason));
  process.on("unhandledRejection", onUnhandled);
  let error = null;
  let returned = [];
  context.responses = [];
  try {
    context.replyThrows = !!options.replyThrows;
    returned = fn(context, listeners) || [];
  } catch (caught) {
    error = String(caught);
  }
  await settle();
  process.off("unhandledRejection", onUnhandled);
  return { listeners: listeners.length, returned, calls, responses: context.responses, error, unhandled };
}

const result = { background: {}, "background-returns": {} };
const validSender = { id: "self-extension-id", tab: { id: 7 }, frameId: 3 };
const scenarios = {
  valid: ["browser-ux-scrollbars", validSender],
  "wrong-message": ["other", validSender],
  "object-message": [{ type: "browser-ux-scrollbars" }, validSender],
  "foreign-sender": ["browser-ux-scrollbars", { ...validSender, id: "other-extension" }],
  "missing-tab": ["browser-ux-scrollbars", { id: "self-extension-id", frameId: 3 }],
  "missing-frame": ["browser-ux-scrollbars", { id: "self-extension-id", tab: { id: 7 } }],
  "top-frame": ["browser-ux-scrollbars", { ...validSender, frameId: 0 }],
};
const dispatch = (message, sender) => (context, listeners) => {
  vm.runInContext(source("background.js"), context);
  return listeners.map((listener) =>
    listener(message, sender, (value) => { if (context.replyThrows) throw new Error("response channel gone"); context.responses.push(value); }) === undefined ? "undefined" : "true");
};
for (const [name, [message, sender]] of Object.entries(scenarios)) {
  result.background[name] = await observe({}, dispatch(message, sender));
}
for (const mode of Object.keys(RETURNS)) {
  result["background-returns"][mode] = await observe(
    { insert: mode }, dispatch("browser-ux-scrollbars", validSender));
}
result["closed-response-channel"] = await observe({ replyThrows: true }, dispatch("browser-ux-scrollbars", validSender));
process.stdout.write(JSON.stringify(result) + "\n");
