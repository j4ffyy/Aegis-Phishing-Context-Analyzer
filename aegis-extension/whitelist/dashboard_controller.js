/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Whitelist Dashboard Controller
 * Specification: Implementation Plan §7, §7.1 (Milestone 3.3)
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  // DOM Elements
  var tableBody = document.getElementById('whitelist-table-body');
  var emptyState = document.getElementById('table-empty-state');
  var searchInput = document.getElementById('search-input');
  var totalCountBadge = document.getElementById('stat-total-identities');
  var modalBackdrop = document.getElementById('add-modal-backdrop');
  var btnOpenModal = document.getElementById('btn-open-add-modal');
  var btnCloseModal = document.getElementById('btn-close-modal');
  var btnCancelModal = document.getElementById('btn-cancel-modal');
  var formAddIdentity = document.getElementById('form-add-identity');
  var btnResetDefaults = document.getElementById('btn-reset-defaults');
  var btnExportJson = document.getElementById('btn-export-json');
  var toastContainer = document.getElementById('toast-container');

  // Simulator Elements
  var simSenderName = document.getElementById('sim-sender-name');
  var simSenderEmail = document.getElementById('sim-sender-email');
  var simSpfStatus = document.getElementById('sim-spf-status');
  var simDkimStatus = document.getElementById('sim-dkim-status');
  var btnRunSimulation = document.getElementById('btn-run-simulation');
  var simResultBox = document.getElementById('sim-result-box');
  var simResultBadge = document.getElementById('sim-result-badge');
  var simResultScore = document.getElementById('sim-result-score');
  var simResultReason = document.getElementById('sim-result-reason');
  var presetLegit = document.getElementById('preset-legit');
  var presetNameSpoof = document.getElementById('preset-name-spoof');
  var presetAuthFail = document.getElementById('preset-auth-fail');

  var currentList = [];

  // ---------------------------------------------------------------------------
  // Toast Notifications
  // ---------------------------------------------------------------------------
  function showToast(message, type) {
    type = type || 'success';
    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.innerHTML = '<span>' + (type === 'success' ? '✓' : '⚠') + '</span><span>' + message + '</span>';
    toastContainer.appendChild(toast);
    setTimeout(function () {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 300);
    }, 2800);
  }

  // ---------------------------------------------------------------------------
  // Render Identity Directory
  // ---------------------------------------------------------------------------
  function renderTable(filterQuery) {
    tableBody.innerHTML = '';
    var query = (filterQuery || '').toLowerCase().trim();

    var filtered = currentList.filter(function (item) {
      if (!query) return true;
      return (
        item.email.toLowerCase().includes(query) ||
        (item.displayName && item.displayName.toLowerCase().includes(query)) ||
        (item.role && item.role.toLowerCase().includes(query)) ||
        (item.department && item.department.toLowerCase().includes(query))
      );
    });

    totalCountBadge.textContent = currentList.length;

    if (filtered.length === 0) {
      emptyState.style.display = 'block';
      return;
    }

    emptyState.style.display = 'none';

    filtered.forEach(function (item) {
      var row = document.createElement('tr');

      // Initials for avatar
      var initials = (item.displayName || item.email)
        .split(' ')
        .map(function (n) { return n[0]; })
        .slice(0, 2)
        .join('')
        .toUpperCase();

      var formattedDate = item.addedAt
        ? new Date(item.addedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
        : 'Active';

      row.innerHTML = `
        <td>
          <div class="identity-cell">
            <div class="avatar-circle">${initials}</div>
            <div class="identity-meta">
              <div class="name">${escapeHtml(item.displayName || item.email)}</div>
              <div class="role">${escapeHtml(item.role || 'Trusted Contact')}</div>
            </div>
          </div>
        </td>
        <td>
          <div class="email-cell">
            <div class="email-address">${escapeHtml(item.email)}</div>
            <div class="domain-tag">Domain: @${escapeHtml(item.allowedDomain || 'any')}</div>
          </div>
        </td>
        <td>
          <span class="dept-pill">${escapeHtml(item.department || 'General')}</span>
        </td>
        <td>
          <div class="protection-badges">
            <span class="guard-pill" title="Protected against display name impersonation">Display Guard</span>
            <span class="guard-pill" title="Cryptographic SPF/DKIM verification active">Auth Guard</span>
          </div>
        </td>
        <td style="color: var(--text-dim); font-size: 0.78rem;">
          ${formattedDate}
        </td>
        <td style="text-align: right;">
          <button class="action-icon-btn btn-delete-entry" data-id="${item.id}" data-email="${item.email}" title="Revoke Whitelist Status">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
              <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
            </svg>
          </button>
        </td>
      `;

      tableBody.appendChild(row);
    });

    // Attach delete listeners
    document.querySelectorAll('.btn-delete-entry').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var id = this.getAttribute('data-id');
        var email = this.getAttribute('data-email');
        if (confirm('Revoke trusted whitelist status for "' + email + '"?')) {
          window.AegisWhitelist.removeWhitelistEntry(id || email).then(function () {
            showToast('Identity removed from whitelist: ' + email);
            loadWhitelistData();
          });
        }
      });
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ---------------------------------------------------------------------------
  // Load Whitelist Data
  // ---------------------------------------------------------------------------
  function loadWhitelistData() {
    if (typeof window.AegisWhitelist === 'undefined') {
      console.warn('AegisWhitelist API not loaded');
      return;
    }

    window.AegisWhitelist.getWhitelist().then(function (list) {
      currentList = list || [];
      renderTable(searchInput.value);
    }).catch(function (err) {
      console.error('Failed to load whitelist data:', err);
      showToast('Error loading whitelist directory', 'error');
    });
  }

  // ---------------------------------------------------------------------------
  // Add Identity Modal Controls
  // ---------------------------------------------------------------------------
  function openModal() {
    modalBackdrop.classList.add('open');
    document.getElementById('input-email').focus();
  }

  function closeModal() {
    modalBackdrop.classList.remove('open');
    formAddIdentity.reset();
  }

  btnOpenModal.addEventListener('click', openModal);
  btnCloseModal.addEventListener('click', closeModal);
  btnCancelModal.addEventListener('click', closeModal);
  modalBackdrop.addEventListener('click', function (e) {
    if (e.target === modalBackdrop) closeModal();
  });

  formAddIdentity.addEventListener('submit', function (e) {
    e.preventDefault();

    var email = document.getElementById('input-email').value.trim();
    var displayName = document.getElementById('input-name').value.trim();
    var role = document.getElementById('input-role').value.trim();
    var department = document.getElementById('input-department').value.trim();
    var allowedDomain = document.getElementById('input-domain').value.trim();
    var notes = document.getElementById('input-notes').value.trim();

    if (!email || !email.includes('@')) {
      alert('Please enter a valid email address.');
      return;
    }

    window.AegisWhitelist.addWhitelistEntry({
      email: email,
      displayName: displayName,
      role: role,
      department: department,
      allowedDomain: allowedDomain,
      notes: notes
    }).then(function (record) {
      showToast('Identity added to whitelist: ' + record.email);
      closeModal();
      loadWhitelistData();
    }).catch(function (err) {
      alert('Failed to add identity: ' + err.message);
    });
  });

  // ---------------------------------------------------------------------------
  // Toolbar Search & Actions
  // ---------------------------------------------------------------------------
  searchInput.addEventListener('input', function () {
    renderTable(this.value);
  });

  btnResetDefaults.addEventListener('click', function () {
    if (confirm('Reset whitelist to initial demonstration seed identities?')) {
      window.AegisWhitelist.resetToDefaults().then(function () {
        showToast('Restored default identity seeds');
        loadWhitelistData();
      });
    }
  });

  btnExportJson.addEventListener('click', function () {
    var dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentList, null, 2));
    var dl = document.createElement('a');
    dl.setAttribute('href', dataStr);
    dl.setAttribute('download', 'aegis_whitelist_export_' + new Date().toISOString().slice(0, 10) + '.json');
    dl.click();
    showToast('Exported whitelist directory to JSON');
  });

  // ---------------------------------------------------------------------------
  // Interactive Revocation Simulator (§7.1 Live Demonstration)
  // ---------------------------------------------------------------------------
  function runSimulation() {
    var name = simSenderName.value.trim();
    var email = simSenderEmail.value.trim();
    var spf = simSpfStatus.value === 'pass' ? true : (simSpfStatus.value === 'fail' ? false : null);
    var dkim = simDkimStatus.value === 'pass' ? true : (simDkimStatus.value === 'fail' ? false : null);

    if (!email) {
      alert('Please enter a sender email address for simulation.');
      return;
    }

    var context = {
      senderEmail: email,
      senderName: name,
      spfPass: spf,
      dkimPass: dkim
    };

    window.AegisWhitelist.checkWhitelistStatus(context).then(function (res) {
      simResultBox.className = 'simulator-result-box active ' +
        (res.revoked ? 'result-revoked' : (res.whitelisted ? 'result-safe' : ''));

      if (res.revoked) {
        simResultBadge.textContent = 'AUTO-REVOKED • ' + res.trigger;
        simResultScore.textContent = res.score + '% (CRITICAL)';
        simResultReason.textContent = res.reason;
      } else if (res.whitelisted) {
        simResultBadge.textContent = 'VERIFIED TRUSTED IDENTITY';
        simResultScore.textContent = res.score + '% (SAFE)';
        simResultReason.textContent = res.reason;
      } else {
        simResultBadge.textContent = 'NOT WHITELISTED';
        simResultScore.textContent = 'Standard AI Analysis';
        simResultReason.textContent = 'Sender is not in the whitelist directory. Evaluates via standard 4-layer threat pipeline.';
      }
    });
  }

  btnRunSimulation.addEventListener('click', runSimulation);

  // Preset Buttons
  presetLegit.addEventListener('click', function () {
    simSenderName.value = 'BDO Merchant Services';
    simSenderEmail.value = 'payroll@trusted-bank.ph';
    simSpfStatus.value = 'pass';
    simDkimStatus.value = 'pass';
    runSimulation();
  });

  presetNameSpoof.addEventListener('click', function () {
    simSenderName.value = 'Executive Director';
    simSenderEmail.value = 'exec.director.urgent@gmail.com';
    simSpfStatus.value = 'pass';
    simDkimStatus.value = 'pass';
    runSimulation();
  });

  presetAuthFail.addEventListener('click', function () {
    simSenderName.value = 'Executive Director';
    simSenderEmail.value = 'executive.director@sme-corp.com';
    simSpfStatus.value = 'fail';
    simDkimStatus.value = 'pass';
    runSimulation();
  });

  // Initial Load
  loadWhitelistData();
});
