/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Popup Script (Controls & Actions)
 */

document.addEventListener('DOMContentLoaded', () => {
  const btnClose = document.getElementById('btn-close');
  const btnReload = document.getElementById('btn-reload');
  const btnRescan = document.getElementById('btn-rescan');
  const btnDashboard = document.getElementById('btn-dashboard');
  const btnReloadExt = document.getElementById('btn-reload-ext');
  const toastMsg = document.getElementById('toast-msg');
  const toastText = document.getElementById('toast-text');

  let toastTimer = null;

  function showToast(text, duration = 2200) {
    if (toastTimer) clearTimeout(toastTimer);
    toastText.textContent = text;
    toastMsg.classList.add('show');
    toastTimer = setTimeout(() => {
      toastMsg.classList.remove('show');
    }, duration);
  }

  // 1. Close Button Handler
  if (btnClose) {
    btnClose.addEventListener('click', () => {
      window.close();
    });
  }

  // 2. Reload & Re-scan Logic
  // Always performs a full Gmail tab reload so the entire Aegis analysis
  // pipeline re-runs from scratch — consistent with the in-overlay reload buttons.
  function triggerReload() {
    if (btnReload) {
      btnReload.classList.add('spinning');
    }

    showToast('Refreshing Gmail tab...');

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs && tabs[0];
      const isGmail = activeTab && activeTab.url && activeTab.url.includes('mail.google.com');

      if (isGmail && activeTab.id) {
        // Full tab reload — the entire Aegis pipeline re-runs on page load
        chrome.tabs.reload(activeTab.id, {}, () => {
          window.close(); // Close popup after reload is dispatched
        });
      } else {
        showToast('Aegis active \u2022 Open Gmail to scan');
      }

      setTimeout(() => {
        if (btnReload) btnReload.classList.remove('spinning');
      }, 750);
    });
  }

  if (btnReload) {
    btnReload.addEventListener('click', triggerReload);
  }

  if (btnRescan) {
    btnRescan.addEventListener('click', triggerReload);
  }

  // 3. Full Extension Reload
  if (btnReloadExt) {
    btnReloadExt.addEventListener('click', (e) => {
      e.preventDefault();
      showToast('Restarting Aegis runtime...');
      setTimeout(() => {
        chrome.runtime.reload();
      }, 400);
    });
  }

  // 4. Whitelist Dashboard
  if (btnDashboard) {
    btnDashboard.addEventListener('click', () => {
      const dashboardUrl = chrome.runtime.getURL('whitelist/whitelist_dashboard.html');
      chrome.tabs.create({ url: dashboardUrl });
      window.close();
    });
  }
});
