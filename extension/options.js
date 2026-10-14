// PhishShield AI — options page.

const CFG = { apiBase: "http://localhost:8000/api/v1", enabled: true };

chrome.storage.local.get(CFG, (stored) => {
  document.getElementById("apiBase").value = stored.apiBase;
  document.getElementById("enabled").checked = stored.enabled !== false;
});

document.getElementById("save").addEventListener("click", () => {
  const value = document.getElementById("apiBase").value.trim().replace(/\/+$/, "");
  chrome.storage.local.set({ apiBase: value || CFG.apiBase, enabled: document.getElementById("enabled").checked })
    .then(() => {
      const el = document.getElementById("saved");
      el.classList.remove("hidden");
      setTimeout(() => el.classList.add("hidden"), 1500);
    });
});