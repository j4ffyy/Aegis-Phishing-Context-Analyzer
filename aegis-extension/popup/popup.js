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

  // 4. Whitelist Admin Dashboard
  if (btnDashboard) {
    btnDashboard.addEventListener('click', () => {
      const dashboardUrl = chrome.runtime.getURL('whitelist/whitelist_dashboard.html');
      chrome.tabs.create({ url: dashboardUrl });
      window.close();
    });
  }

  // 5. SME Analytics Dashboard (PR-04)
  const btnSmeDashboard = document.getElementById('btn-sme-dashboard');
  if (btnSmeDashboard) {
    btnSmeDashboard.addEventListener('click', () => {
      const smeDashboardUrl = chrome.runtime.getURL('dashboard/dashboard.html');
      chrome.tabs.create({ url: smeDashboardUrl });
      window.close();
    });
  }

  // 6. Backend Connectivity Live Probe (PR-10)
  const backendDot  = document.getElementById('backend-status-dot');
  const backendText = document.getElementById('backend-status-text');
  const backendPill = document.getElementById('backend-status-pill');
  const statusDesc  = document.getElementById('status-desc');

  function setBackendStatus(isOnline) {
    if (!backendDot || !backendText || !backendPill) return;

    if (isOnline) {
      backendDot.className = 'backend-status-dot online';
      backendText.textContent = 'Remote ML Backend Connected';
      backendPill.className = 'backend-status-pill online';
      backendPill.textContent = 'ONLINE';
      if (statusDesc) {
        statusDesc.textContent = 'Aegis is actively monitoring email threads with multi-tier ML defense.';
      }
    } else {
      backendDot.className = 'backend-status-dot offline';
      backendText.textContent = 'Offline Heuristic Mode Active';
      backendPill.className = 'backend-status-pill offline';
      backendPill.textContent = 'OFFLINE MODE';
      if (statusDesc) {
        statusDesc.textContent = 'Protection running in Offline Heuristic Mode — relying on local behavioral baseline and cached threat rules.';
      }
    }
  }

  function checkBackendConnectivity() {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
      setBackendStatus(false);
      return;
    }

    try {
      chrome.runtime.sendMessage({ action: 'AEGIS_CHECK_HEALTH' }, (response) => {
        const isHealthy = Boolean(
          !chrome.runtime.lastError &&
          response &&
          response.success &&
          response.data &&
          (response.data.status === 'healthy' || response.data.status === 'ok')
        );
        setBackendStatus(isHealthy);
      });
    } catch {
      setBackendStatus(false);
    }
  }

  checkBackendConnectivity();
});

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    // Export helpers for headless testing if needed
  };
}

