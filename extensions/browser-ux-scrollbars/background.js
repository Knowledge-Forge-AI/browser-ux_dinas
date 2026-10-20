"use strict";
// Browser UX scrollbar visibility & manual top-layer rail host.
// Injects scrollbars.css (native property restoration) and rail-host.css (popover host protection)
// with USER origin.

const MESSAGE = "browser-ux-scrollbars";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message !== MESSAGE || sender.id !== chrome.runtime.id) {
    return;
  }
  const tabId = sender.tab && sender.tab.id;
  const frameId = sender.frameId;
  if (!Number.isInteger(tabId) || !Number.isInteger(frameId)) {
    return;
  }

  const reply = (ok) => {
    try { sendResponse({ ok }); } catch {}
  };
  try {
    const insertion = chrome.scripting.insertCSS({
      target: { tabId, frameIds: [frameId] },
      files: ["scrollbars.css", "rail-host.css"],
      origin: "USER",
    });
    if (insertion && typeof insertion.then === "function") {
      Promise.resolve(insertion).then(
        () => {
          reply(true);
        },
        () => {
          reply(false);
        },
      );
    } else {
      reply(false);
    }
  } catch {
    reply(false);
  }

  return true;
});
