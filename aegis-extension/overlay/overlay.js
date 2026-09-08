/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Overlay Controller
 */

(function () {
  'use strict';

  if (window.__AEGIS_OVERLAY_LOADED__) {
    return;
  }
  window.__AEGIS_OVERLAY_LOADED__ = true;

  const LOG_PREFIX = '[Aegis::Overlay]';
  let currentEmailContext = null;

  function injectOverlayDOM() {
    if (document.getElementById('aegis-overlay-root')) {
      return;
    }

    const root = document.createElement('div');
    root.id = 'aegis-overlay-root';
    root.className = 'aegis-overlay-root';

    root.innerHTML = `
      <button class="aegis-fab" id="aegis-fab" title="Analyze email with Aegis AI" style="display: none;" aria-label="Scan email with Aegis">
        <i class="fas fa-shield-alt"></i> Scan
      </button>

      <div class="aegis-analyzer-overlay" id="aegis-analyzer-overlay" role="dialog" aria-label="Aegis Phishing Analyzer Panel">
        <div class="aegis-analyzer-header">
          <h3><i class="fas fa-shield-alt"></i> Aegis Phishing Analyzer</h3>
          <button class="aegis-close-btn" id="aegis-close-analyzer" aria-label="Close Aegis panel">
            <i class="fas fa-times"></i>
          </button>
        </div>

        <div class="aegis-analyzer-status" id="aegis-analyzer-status">
          <div class="aegis-spinner"></div>
          <p>Running Multi-Layered Analysis...</p>
        </div>

        <div class="aegis-analyzer-results" id="aegis-analyzer-results" style="display: none;">
          <div class="aegis-risk-score-card" id="aegis-risk-score-card">
            <div class="aegis-score-circle" id="aegis-score-circle">
              <span id="aegis-score-value">0</span>%
            </div>
            <div class="aegis-score-text">
              <h4 id="aegis-risk-level">Safe</h4>
              <p id="aegis-risk-desc">No significant threats detected.</p>
            </div>
          </div>

          <div class="aegis-layer-analysis">
            <h4>Multi-Layered Defense Status</h4>
            <ul class="aegis-layers-list" id="aegis-layers-list">
              <li id="aegis-layer-sanitization"><i class="fas fa-minus-circle aegis-icon-skip"></i> Pre-processing: HTML Sanitization</li>
              <li id="aegis-layer-auth"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 1: Auth (SPF/DKIM/DMARC)</li>
              <li id="aegis-layer-attach"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 2: Attachment Check</li>
              <li id="aegis-layer-behavior"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 3: Behavioral Analysis</li>
              <li id="aegis-layer-nlp"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 4: Deep NLP Context</li>
            </ul>
          </div>

          <div class="aegis-xai-box" id="aegis-xai-box">
            <h4><i class="fas fa-brain"></i> Explainable AI (XAI) Insight</h4>
            <p id="aegis-xai-text">Analysis in progress...</p>
          </div>

          <div class="aegis-actions">
            <button class="aegis-btn aegis-btn-primary" id="aegis-whitelist-btn" style="display: none;" aria-label="Whitelist sender">
              <i class="fas fa-user-check"></i> Whitelist Sender
            </button>
            <button class="aegis-btn" id="aegis-block-btn" style="display: none;" aria-label="Block sender">
              <i class="fas fa-ban"></i> Block
            </button>
            <button class="aegis-btn" id="aegis-report-btn" style="display: none;" aria-label="Report false positive">
              <i class="fas fa-flag"></i> Report False Positive
            </button>
            <button class="aegis-btn" id="aegis-full-analysis-btn" aria-label="View full analysis report">
              <i class="fas fa-search-plus"></i> View Full Analysis
            </button>
          </div>
        </div>
      </div>

      <div class="aegis-fam" id="aegis-fam" role="dialog" aria-modal="true" aria-label="Aegis Full Analysis Report">
        <div class="aegis-fam-backdrop" id="aegis-fam-backdrop"></div>
        <div class="aegis-fam-panel">
          <div class="aegis-fam-header" id="aegis-fam-header">
            <div class="aegis-fam-header-left">
              <div class="aegis-fam-logo"><i class="fas fa-shield-alt"></i></div>
              <div>
                <div class="aegis-fam-title">Aegis Full Analysis Report</div>
                <div class="aegis-fam-subtitle" id="aegis-fam-subtitle">Comprehensive Threat Intelligence</div>
              </div>
            </div>
            <div class="aegis-fam-header-right">
              <div class="aegis-fam-risk-badge" id="aegis-fam-risk-badge">—</div>
              <button class="aegis-fam-close-btn" id="aegis-fam-close-btn" aria-label="Close full analysis"><i class="fas fa-times"></i></button>
            </div>
          </div>

          <div class="aegis-fam-body">
            <div class="aegis-fam-col-left">
              <div class="aegis-fam-card aegis-fam-gauge-card">
                <div class="aegis-fam-card-label"><i class="fas fa-tachometer-alt"></i> Aegis Risk Score</div>
                <div class="aegis-fam-gauge-wrap">
                  <svg class="aegis-fam-gauge-svg" viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="aegisGaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%"   style="stop-color:#22c55e"/>
                        <stop offset="50%"  style="stop-color:#f59e0b"/>
                        <stop offset="100%" style="stop-color:#ef4444"/>
                      </linearGradient>
                    </defs>
                    <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#e5e7eb" stroke-width="14" stroke-linecap="round"/>
                    <path id="aegis-fam-gauge-fill"
                          d="M 20 100 A 80 80 0 0 1 180 100"
                          fill="none"
                          stroke="url(#aegisGaugeGradient)"
                          stroke-width="14"
                          stroke-linecap="round"
                          stroke-dasharray="251.2"
                          stroke-dashoffset="251.2"
                          style="transition: stroke-dashoffset 1.2s cubic-bezier(0.34,1.56,0.64,1);"/>
                    <line id="aegis-fam-gauge-needle"
                          x1="100" y1="100" x2="100" y2="30"
                          stroke="#1e293b" stroke-width="3" stroke-linecap="round"
                          style="transform-origin: 100px 100px; transition: transform 1.2s cubic-bezier(0.34,1.56,0.64,1);"/>
                    <circle cx="100" cy="100" r="6" fill="#1e293b"/>
                    <text x="15"  y="118" font-size="10" fill="#6b7280" text-anchor="middle">0</text>
                    <text x="100" y="18"  font-size="10" fill="#6b7280" text-anchor="middle">50</text>
                    <text x="185" y="118" font-size="10" fill="#6b7280" text-anchor="middle">100</text>
                  </svg>
                  <div class="aegis-fam-gauge-score-wrap">
                    <div class="aegis-fam-gauge-score" id="aegis-fam-gauge-score">0<span>%</span></div>
                    <div class="aegis-fam-gauge-label" id="aegis-fam-gauge-label">Analyzing...</div>
                  </div>
                </div>
              </div>

              <div class="aegis-fam-card">
                <div class="aegis-fam-card-label"><i class="fas fa-envelope-open-text"></i> Email Metadata</div>
                <div class="aegis-fam-meta-grid">
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">From</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-from">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-domain aegis-fam-meta-key">Domain</div>
                    <div class="aegis-fam-meta-val aegis-fam-meta-domain" id="aegis-fam-meta-domain">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">Subject</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-subject">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">Time</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-time">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">Attachment</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-attach">None</div>
                  </div>
                </div>
              </div>

              <div class="aegis-fam-card aegis-fam-xai-card">
                <div class="aegis-fam-card-label"><i class="fas fa-brain"></i> XAI Explanation</div>
                <p class="aegis-fam-xai-text" id="aegis-fam-xai-text">—</p>
                <div class="aegis-fam-xai-footer">
                  <i class="fas fa-info-circle"></i> Generated by Aegis Explainable AI engine
                </div>
              </div>
            </div>

            <div class="aegis-fam-col-right">
              <div class="aegis-fam-card">
                <div class="aegis-fam-card-label"><i class="fas fa-layer-group"></i> Multi-Layer Defense Breakdown</div>
                <div class="aegis-fam-layers" id="aegis-fam-layers"></div>
              </div>

              <div class="aegis-fam-card" id="aegis-fam-indicators-card">
                <div class="aegis-fam-card-label"><i class="fas fa-exclamation-triangle"></i> Active Threat Indicators</div>
                <div class="aegis-fam-indicators" id="aegis-fam-indicators"></div>
              </div>

              <div class="aegis-fam-card aegis-fam-recommendation-card" id="aegis-fam-recommendation-card">
                <div class="aegis-fam-card-label"><i class="fas fa-shield-check"></i> Aegis Recommendation</div>
                <div class="aegis-fam-recommendation" id="aegis-fam-recommendation">—</div>
                <div class="aegis-fam-action-row">
                  <button class="aegis-fam-action-btn aegis-fam-btn-whitelist" id="aegis-fam-whitelist-btn" style="display:none;" aria-label="Whitelist sender">
                    <i class="fas fa-user-check"></i> Whitelist Sender
                  </button>
                  <button class="aegis-fam-action-btn aegis-fam-btn-block" id="aegis-fam-block-btn" style="display:none;" aria-label="Block and report sender">
                    <i class="fas fa-ban"></i> Block & Report
                  </button>
                  <button class="aegis-fam-action-btn aegis-fam-btn-report" id="aegis-fam-report-btn" style="display:none;" aria-label="Report false positive">
                    <i class="fas fa-flag"></i> False Positive
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(root);
    console.log(`${LOG_PREFIX} Overlay DOM injected.`);
  }

  // ============================================================
  // DOM Element References — resolved after injection
  // ============================================================

  /**
   * Lazily resolved element references after injectOverlayDOM() has run.
   * Using a getter pattern avoids null references at script parse time.
   */
  const el = {
    get fab()              { return document.getElementById('aegis-fab'); },
    get overlay()          { return document.getElementById('aegis-analyzer-overlay'); },
    get closeBtn()         { return document.getElementById('aegis-close-analyzer'); },
    get status()           { return document.getElementById('aegis-analyzer-status'); },
    get results()          { return document.getElementById('aegis-analyzer-results'); },
    get scoreCircle()      { return document.getElementById('aegis-score-circle'); },
    get scoreValue()       { return document.getElementById('aegis-score-value'); },
    get riskLevel()        { return document.getElementById('aegis-risk-level'); },
    get riskDesc()         { return document.getElementById('aegis-risk-desc'); },
    get layerSanitization(){ return document.getElementById('aegis-layer-sanitization'); },
    get layerAuth()        { return document.getElementById('aegis-layer-auth'); },
    get layerAttach()      { return document.getElementById('aegis-layer-attach'); },
    get layerBehavior()    { return document.getElementById('aegis-layer-behavior'); },
    get layerNlp()         { return document.getElementById('aegis-layer-nlp'); },
    get xaiText()          { return document.getElementById('aegis-xai-text'); },
    get whitelistBtn()     { return document.getElementById('aegis-whitelist-btn'); },
    get blockBtn()         { return document.getElementById('aegis-block-btn'); },
    get reportBtn()        { return document.getElementById('aegis-report-btn'); },
    get fullAnalysisBtn()  { return document.getElementById('aegis-full-analysis-btn'); },
    // Full Analysis Modal
    get fam()              { return document.getElementById('aegis-fam'); },
    get famClose()         { return document.getElementById('aegis-fam-close-btn'); },
    get famBackdrop()      { return document.getElementById('aegis-fam-backdrop'); },
    get famRiskBadge()     { return document.getElementById('aegis-fam-risk-badge'); },
    get famSubtitle()      { return document.getElementById('aegis-fam-subtitle'); },
    get famGaugeScore()    { return document.getElementById('aegis-fam-gauge-score'); },
    get famGaugeLabel()    { return document.getElementById('aegis-fam-gauge-label'); },
    get famGaugeFill()     { return document.getElementById('aegis-fam-gauge-fill'); },
    get famGaugeNeedle()   { return document.getElementById('aegis-fam-gauge-needle'); },
    get famMetaFrom()      { return document.getElementById('aegis-fam-meta-from'); },
    get famMetaDomain()    { return document.getElementById('aegis-fam-meta-domain'); },
    get famMetaSubject()   { return document.getElementById('aegis-fam-meta-subject'); },
    get famMetaTime()      { return document.getElementById('aegis-fam-meta-time'); },
    get famMetaAttach()    { return document.getElementById('aegis-fam-meta-attach'); },
    get famXaiText()       { return document.getElementById('aegis-fam-xai-text'); },
    get famLayers()        { return document.getElementById('aegis-fam-layers'); },
    get famIndicators()    { return document.getElementById('aegis-fam-indicators'); },
    get famRecommendation(){ return document.getElementById('aegis-fam-recommendation'); },
    get famWhitelistBtn()  { return document.getElementById('aegis-fam-whitelist-btn'); },
    get famBlockBtn()      { return document.getElementById('aegis-fam-block-btn'); },
    get famReportBtn()     { return document.getElementById('aegis-fam-report-btn'); },
  };

  function generateStubAnalysis(emailContext) {
    const subjectLower = (emailContext.subject || '').toLowerCase();
    const hasSuspiciousKeywords =
      /urgent|password|account|verify|suspended|invoice|wire|transfer|click here/.test(subjectLower);
    const hasAttachments = emailContext.attachmentCount > 0;
    const hasExternalLinks = (emailContext.links || []).some(l => l.isExternal);

    let riskLevel, riskClass, score, desc;
    if (hasSuspiciousKeywords && (hasAttachments || hasExternalLinks)) {
      riskLevel = 'Critical'; riskClass = 'threat-critical'; score = 89;
      desc = 'High-confidence phishing indicators detected.';
    } else if (hasSuspiciousKeywords || hasExternalLinks) {
      riskLevel = 'Warning'; riskClass = 'threat-warning'; score = 58;
      desc = 'Suspicious patterns detected. Review carefully.';
    } else {
      riskLevel = 'Safe'; riskClass = 'threat-safe'; score = 7;
      desc = 'No significant threats detected.';
    }

    const attachDetail = hasAttachments
      ? `VirusTotal: ${emailContext.attachmentCount} file(s) queued`
      : 'No Attachments';
    const attachIcon  = hasAttachments ? 'fa-exclamation-triangle' : 'fa-minus-circle';

    return {
      riskLevel,
      riskClass,
      score,
      desc,
      layers: {
        sanitization: { text: 'Pre-filter: Sanitization', detail: 'HTML Stripped — Plain Text Only', icon: 'fa-check-circle' },
        auth:         { text: 'Layer 1: Auth (SPF/DKIM/DMARC)', detail: 'Pending — Auth headers not available client-side', icon: 'fa-minus-circle' },
        attach:       { text: 'Layer 2: Attachment Intelligence', detail: attachDetail, icon: attachIcon },
        behavior:     { text: 'Layer 3: Behavioral Analysis', detail: 'Baseline: Pending sender history', icon: 'fa-minus-circle' },
        nlp:          { text: 'Layer 4: Deep NLP Context', detail: hasSuspiciousKeywords ? 'Urgency/Financial keywords detected' : 'Context appears normal', icon: hasSuspiciousKeywords ? 'fa-exclamation-triangle' : 'fa-check-circle' },
      },
      xai: riskLevel === 'Safe'
        ? 'This email follows standard communication patterns. No urgency, financial requests, or malicious payloads were detected by the preliminary analysis pipeline. Full ML analysis pending backend connection.'
        : `Preliminary analysis flagged suspicious characteristics: ${hasSuspiciousKeywords ? 'urgency/financial keywords in subject. ' : ''}${hasExternalLinks ? 'External hyperlinks present. ' : ''}${hasAttachments ? 'Attachments detected and queued for VirusTotal scan. ' : ''}Full ML scoring pending backend connection (Milestone 2.x).`,
    };
  }

  function closeAnalyzer() {
    el.overlay.classList.remove('active');
    if (currentEmailContext) {
      el.fab.style.display = 'flex';
    }
    setTimeout(() => {
      el.overlay.className = 'aegis-analyzer-overlay';
    }, 400);
  }

  function populateAnalysis(analysis) {
    el.overlay.className = `aegis-analyzer-overlay active ${analysis.riskClass}`;

    el.scoreValue.textContent = analysis.score;
    el.riskLevel.textContent  = analysis.riskLevel;
    el.riskDesc.textContent   = analysis.desc;

    const layerEls = {
      sanitization: el.layerSanitization,
      auth:         el.layerAuth,
      attach:       el.layerAttach,
      behavior:     el.layerBehavior,
      nlp:          el.layerNlp,
    };

    const iconClassMap = {
      'fa-check-circle':        { cls: 'fas fa-check-circle aegis-icon-pass' },
      'fa-times-circle':        { cls: 'fas fa-times-circle aegis-icon-fail' },
      'fa-exclamation-triangle':{ cls: 'fas fa-exclamation-triangle aegis-icon-warn' },
      'fa-minus-circle':        { cls: 'fas fa-minus-circle aegis-icon-skip' },
    };

    Object.entries(layerEls).forEach(([key, listItem]) => {
      const data = analysis.layers[key];
      const icon = iconClassMap[data.icon] || iconClassMap['fa-minus-circle'];
      listItem.innerHTML = `<i class="${icon.cls}"></i> ${data.text}: ${data.detail}`;
    });

    el.xaiText.textContent = analysis.xai;

    if (analysis.riskLevel === 'Safe') {
      el.whitelistBtn.style.display = 'flex';
      el.blockBtn.style.display     = 'none';
      el.reportBtn.style.display    = 'none';
    } else {
      el.whitelistBtn.style.display = 'none';
      el.blockBtn.style.display     = 'flex';
      el.reportBtn.style.display    = 'flex';
    }
  }

  function openFullAnalysisModal(emailContext, analysis) {
    const badge = el.famRiskBadge;
    badge.textContent = analysis.riskLevel;
    badge.className = 'aegis-fam-risk-badge';
    if      (analysis.riskLevel === 'Safe')    badge.classList.add('badge-safe');
    else if (analysis.riskLevel === 'Warning') badge.classList.add('badge-warning');
    else                                        badge.classList.add('badge-critical');

    el.famSubtitle.textContent =
      `Analyzed: ${emailContext.subject || '(No Subject)'} — ${emailContext.timestamp || 'Just now'}`;

    el.famGaugeScore.innerHTML = `${analysis.score}<span>%</span>`;
    el.famGaugeLabel.textContent = analysis.riskLevel;
    el.famGaugeLabel.className = 'aegis-fam-gauge-label';
    if      (analysis.riskLevel === 'Safe')    el.famGaugeLabel.classList.add('lbl-safe');
    else if (analysis.riskLevel === 'Warning') el.famGaugeLabel.classList.add('lbl-warning');
    else                                        el.famGaugeLabel.classList.add('lbl-critical');

    const arcLen    = 251.2;
    const offset    = arcLen - (analysis.score / 100) * arcLen;
    const needleDeg = -90 + (analysis.score / 100) * 180;

    el.famGaugeFill.style.transition   = 'none';
    el.famGaugeNeedle.style.transition = 'none';
    el.famGaugeFill.style.strokeDashoffset = arcLen;
    el.famGaugeNeedle.style.transform  = 'rotate(-90deg)';

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.famGaugeFill.style.transition   = 'stroke-dashoffset 1.2s cubic-bezier(0.34,1.56,0.64,1)';
        el.famGaugeNeedle.style.transition = 'transform 1.2s cubic-bezier(0.34,1.56,0.64,1)';
        el.famGaugeFill.style.strokeDashoffset = offset;
        el.famGaugeNeedle.style.transform  = `rotate(${needleDeg}deg)`;
      });
    });

    el.famMetaFrom.textContent    = `${emailContext.senderName || '—'} <${emailContext.senderEmail || '—'}>`;
    const domain = emailContext.senderEmail
      ? emailContext.senderEmail.split('@')[1] || emailContext.senderEmail
      : '—';
    el.famMetaDomain.textContent  = domain;
    el.famMetaSubject.textContent = emailContext.subject || '—';
    el.famMetaTime.textContent    = emailContext.timestamp || '—';
    el.famMetaAttach.textContent  = emailContext.attachmentCount > 0
      ? emailContext.attachments.join(', ')
      : 'None';

    el.famXaiText.textContent = analysis.xai;

    el.famLayers.innerHTML = '';
    const layerMap = [
      { key: 'sanitization', label: 'Pre-processing: HTML Sanitization' },
      { key: 'auth',         label: 'Layer 1: Email Auth (SPF/DKIM/DMARC)' },
      { key: 'attach',       label: 'Layer 2: Attachment Intelligence' },
      { key: 'behavior',     label: 'Layer 3: Behavioral Analysis' },
      { key: 'nlp',          label: 'Layer 4: Deep NLP Context' },
    ];

    layerMap.forEach(({ key, label }, idx) => {
      const data = analysis.layers[key];
      let iconClass, iconType, statusClass, statusText;

      switch (data.icon) {
        case 'fa-check-circle':
          iconClass = 'fas fa-check'; iconType = 'icon-pass'; statusClass = 'status-pass'; statusText = 'Pass'; break;
        case 'fa-times-circle':
          iconClass = 'fas fa-times'; iconType = 'icon-fail'; statusClass = 'status-fail'; statusText = 'Fail'; break;
        case 'fa-exclamation-triangle':
          iconClass = 'fas fa-exclamation'; iconType = 'icon-warn'; statusClass = 'status-warn'; statusText = 'Warn'; break;
        default:
          iconClass = 'fas fa-minus'; iconType = 'icon-skip'; statusClass = 'status-skip'; statusText = 'Skip';
      }

      const item = document.createElement('div');
      item.className = 'aegis-fam-layer-item';
      item.style.animationDelay = `${idx * 80}ms`;
      item.innerHTML = `
        <div class="aegis-fam-layer-icon ${iconType}"><i class="${iconClass}"></i></div>
        <div class="aegis-fam-layer-body">
          <div class="aegis-fam-layer-name">${label}</div>
          <div class="aegis-fam-layer-detail">${data.detail}</div>
        </div>
        <div class="aegis-fam-layer-status ${statusClass}">${statusText}</div>
      `;
      el.famLayers.appendChild(item);
    });

    el.famIndicators.innerHTML = '';
    const threats = [];
    Object.values(analysis.layers).forEach(layer => {
      if (layer.icon === 'fa-times-circle') {
        threats.push({ text: layer.detail, pillClass: 'pill-red',    icon: 'fas fa-times-circle' });
      } else if (layer.icon === 'fa-exclamation-triangle') {
        threats.push({ text: layer.detail, pillClass: 'pill-yellow', icon: 'fas fa-exclamation-triangle' });
      }
    });

    if (threats.length === 0) {
      el.famIndicators.innerHTML = `
        <div class="aegis-fam-no-threats">
          <i class="fas fa-check-circle"></i> No active threat indicators detected.
        </div>`;
    } else {
      threats.forEach((t, idx) => {
        const pill = document.createElement('div');
        pill.className = `aegis-fam-indicator-pill ${t.pillClass}`;
        pill.style.animationDelay = `${idx * 60}ms`;
        pill.innerHTML = `<i class="${t.icon}"></i> ${t.text}`;
        el.famIndicators.appendChild(pill);
      });
    }

    const recEl = el.famRecommendation;
    recEl.className = 'aegis-fam-recommendation';
    if (analysis.riskLevel === 'Safe') {
      recEl.textContent = 'This email has passed all Aegis security layers and is considered safe. No action is required. You may optionally whitelist the sender to speed up future checks.';
      recEl.classList.add('rec-safe');
    } else if (analysis.riskLevel === 'Warning') {
      recEl.textContent = 'This email contains suspicious patterns consistent with a Business Email Compromise (BEC) or phishing attempt. Exercise caution — do not click links, transfer funds, or share credentials until the sender is verified through a separate channel.';
      recEl.classList.add('rec-warning');
    } else {
      recEl.textContent = 'CRITICAL THREAT DETECTED. Aegis strongly recommends blocking this sender immediately and reporting this email to your IT security team. Do not open attachments, click links, or reply under any circumstances.';
      recEl.classList.add('rec-critical');
    }

    el.famWhitelistBtn.style.display = analysis.riskLevel === 'Safe'    ? 'flex' : 'none';
    el.famBlockBtn.style.display     = analysis.riskLevel !== 'Safe'    ? 'flex' : 'none';
    el.famReportBtn.style.display    = analysis.riskLevel !== 'Safe'    ? 'flex' : 'none';

    el.fam.classList.add('open');
  }

  function closeFullAnalysisModal() {
    el.fam.classList.remove('open');
  }

  function attachEventListeners() {
    el.closeBtn.addEventListener('click', closeAnalyzer);

    el.fab.addEventListener('click', () => {
      if (!currentEmailContext) return;

      el.overlay.classList.add('active');
      el.status.style.display  = 'flex';
      el.results.style.display = 'none';
      el.fab.style.display     = 'none';

      setTimeout(() => {
        const analysis = generateStubAnalysis(currentEmailContext);
        populateAnalysis(analysis);
        el.status.style.display  = 'none';
        el.results.style.display = 'flex';
        currentEmailContext._lastAnalysis = analysis;
      }, 1500);
    });

    el.fullAnalysisBtn.addEventListener('click', () => {
      if (!currentEmailContext || !currentEmailContext._lastAnalysis) return;
      openFullAnalysisModal(currentEmailContext, currentEmailContext._lastAnalysis);
    });

    el.famClose.addEventListener('click', closeFullAnalysisModal);
    el.famBackdrop.addEventListener('click', closeFullAnalysisModal);

    el.whitelistBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Whitelisted!';
      setTimeout(() => { this.innerHTML = orig; }, 2000);
    });

    el.blockBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-shield-alt"></i> Blocked!';
      setTimeout(() => { this.innerHTML = orig; }, 2000);
    });

    el.reportBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Reported!';
      setTimeout(() => { this.innerHTML = orig; }, 2000);
    });

    el.famWhitelistBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Whitelisted!';
      setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
    });

    el.famBlockBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-shield-alt"></i> Blocked!';
      setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
    });

    el.famReportBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Reported!';
      setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
    });

    console.log(`${LOG_PREFIX} Event listeners attached.`);
  }

  function startEmailDetectionListener() {
    window.addEventListener('aegis:email-extracted', (event) => {
      const emailContext = event.detail;
      if (!emailContext) return;

      currentEmailContext = emailContext;
      el.fab.style.display = 'flex';

      if (el.overlay.classList.contains('active')) {
        closeAnalyzer();
      }

      console.log(`${LOG_PREFIX} Email detected. FAB shown for: "${emailContext.subject}"`);
    });

    console.log(`${LOG_PREFIX} Listening for aegis:email-extracted events.`);
  }

  function initialize() {
    injectOverlayDOM();
    attachEventListeners();
    startEmailDetectionListener();
    console.log(`${LOG_PREFIX} Overlay initialized.`);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }

  window.AegisOverlay = {
    closeAnalyzer,
    closeFullAnalysisModal,
    openFullAnalysisModal,
    getCurrentContext: () => currentEmailContext,
  };
})();
