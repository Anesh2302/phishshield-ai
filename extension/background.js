// PhishShield AI background service worker (MV3).
// Why <all_urls>: the popup and context menu need to check the active tab's URL.
// Scope is minimised: we only call the local PhishShield API configured in options.

const DEFAULTS = { apiBase: "http://localhost:8000/api/v1", enabled: true };

async function cfg() {
  const stored = (await chrome.storage.local.get(DEFAULTS)) || {};
  return {
    apiBase: stored.apiBase || DEFAULTS.apiBase,
    enabled: stored.enabled !== false,
  };
}

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set(DEFAULTS);
});

chrome.action.onClicked.addListener(() => chrome.tabs.create({ url: "options.html" }));

chrome.contextMenus.removeAll(() => {
  chrome.contextMenus.create({
    id: "phishshield-check-link",
    title: "Check this link with PhishShield AI",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "phishshield-options",
    title: "PhishShield AI options",
    contexts: ["action"],
  });
  chrome.contextMenus.create({
    id: "phishshield-open-console",
    title: "Open PhishShield AI console",
    contexts: ["action"],
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "phishshield-options") {
    chrome.runtime.openOptionsPage();
  }
  if (info.menuItemId === "phishshield-open-console") {
    chrome.tabs.create({ url: "http://localhost:3000" });
  }
  if (info.menuItemId === "phishshield-check-link") {
    chrome.storage.local.set({ pendingCheck: info.linkUrl || "" });
    chrome.action.openPopup().catch(() => {});
  }
});

// Highlights: when we know a page is bad, tag the tab so the popup can warn fast.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "phishshield-set-tab") {
    chrome.storage.local.set({ lastTab: msg.data }).then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});