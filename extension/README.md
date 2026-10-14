# PhishShield AI — Chrome / Chromium extension (MV3)

A local-first companion to the PhishShield AI backend. No cloud service is
contacted; every check goes to the API base URL you configure. Only the single
URL you ask to check is sent — the extension never uploads browsing history.

## What it does

- **Popup**: scans the active tab's URL via `POST /api/v1/scans/url` and shows
  verdict, score, top evidence rules and the recommended action.
- **Context menu**: right-click any link → "Check this link with PhishShield AI".
- **Options**: choose the API base URL (default `http://localhost:8000/api/v1`)
  and enable/disable scanning.

## Load it (Developer Mode)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** (top-right).
3. **Load unpacked** → select this `extension/` folder.
4. Optional: pin the PhishShield AI entry in the toolbar.

The API must be running locally (see the repo README). Because the extension is
loaded unpacked, no CORS restrictions apply; for a signed/packaged build you
would add an explicit host permission for your API origin instead of `"<all_urls>"`.

## Privacy note

The `host_permissions: ["<all_urls>"]` entry exists so the popup can read the
URL of whichever site is in the active tab. Nothing is transmitted until you
trigger a check (or configure automation), and then only the requested URL goes
to your configured backend.

## Icons

`make_icons.py` regenerates the toolbar icons (pure stdlib PNG writer).
Run: `python make_icons.py`.

## Content security

The extension is declarative-only: no remote code, no inline scripts, MV3 service
worker. Shipping it for real would pair the API with TLS + an API token header.