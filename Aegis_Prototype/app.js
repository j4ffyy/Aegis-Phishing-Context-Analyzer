const mockEmails = [
    {
        id: 1,
        senderName: "HR Department",
        senderAddress: "hr@company.com",
        subject: "Q3 Holiday Schedule Updates",
        time: "10:30 AM",
        preview: "Please review the updated holiday schedule for the upcoming quarter...",
        body: `<p>Hi Team,</p><p>Please review the updated holiday schedule for Q3 attached in the company portal. Let us know if you have any questions.</p><p>Best,<br>HR Team</p>`,
        hasAttachment: false,
        attachmentName: null,
        analysis: {
            riskLevel: "Safe",
            riskClass: "threat-safe",
            score: 5,
            desc: "No significant threats detected.",
            layers: {
                sanitization: { text: "Pre-filter: Sanitization", detail: "Clean", icon: "fa-check-circle" },
                auth: { text: "Pre-filter: Auth", detail: "SPF/DKIM/DMARC Pass", icon: "fa-check-circle" },
                attach: { text: "Pre-filter: Attachment Intel", detail: "No Attachments", icon: "fa-minus-circle" },
                behavior: { text: "Core: Behavioral Analysis", detail: "Sender Behavior Normal", icon: "fa-check-circle" },
                nlp: { text: "Core: ML & NLP Pipelines", detail: "Context Clean", icon: "fa-check-circle" }
            },
            xai: "This email follows standard internal communication patterns. No urgency, financial requests, or malicious payloads were detected."
        }
    },
    {
        id: 2,
        senderName: "Billing Support",
        senderAddress: "support@biling-services-update.com",
        subject: "URGENT: Overdue Invoice #94812",
        time: "09:15 AM",
        preview: "Your account is past due. Please open the attached invoice to prevent suspension...",
        body: `<p>Dear Customer,</p><p>Your account is severely past due. If you do not remit payment immediately, your services will be suspended in 24 hours.</p><p>Please download and review the attached invoice for payment details.</p><p>Thank you.</p>`,
        hasAttachment: true,
        attachmentName: "Invoice_94812.pdf",
        analysis: {
            riskLevel: "Critical",
            riskClass: "threat-critical",
            score: 98,
            desc: "High probability of malware and phishing.",
            layers: {
                sanitization: { text: "Pre-filter: Sanitization", detail: "Clean", icon: "fa-check-circle" },
                auth: { text: "Pre-filter: Auth", detail: "Domain Spoofed", icon: "fa-times-circle" },
                attach: { text: "Pre-filter: Attachment Intel", detail: "VirusTotal: Malicious PDF", icon: "fa-times-circle" },
                behavior: { text: "Core: Behavioral Analysis", detail: "First Time Sender", icon: "fa-exclamation-triangle" },
                nlp: { text: "Core: ML & NLP Pipelines", detail: "High Urgency & Financial Req", icon: "fa-times-circle" }
            },
            xai: "Multiple red flags: The attachment contains known malware signatures. The sender domain 'biling-services-update.com' failed DMARC checks. The NLP model detected extreme urgency coupled with a financial demand."
        }
    },
    {
        id: 3,
        senderName: "CEO (John Doe)",
        senderAddress: "john.doe.exec@gmail.com",
        subject: "Confidential Project - Need your help",
        time: "Yesterday",
        preview: "Are you at your desk? I need you to handle a quick confidential wire transfer...",
        body: `<p>Are you at your desk?</p><p>I am currently in a meeting and cannot take calls. I need you to handle a highly confidential wire transfer for a new vendor acquisition immediately. Please let me know once you are ready and I will send the account details.</p><p>Keep this between us for now.</p><p>- John</p>`,
        hasAttachment: false,
        attachmentName: null,
        analysis: {
            riskLevel: "Warning",
            riskClass: "threat-warning",
            score: 85,
            desc: "Suspicious behavioral and contextual patterns.",
            layers: {
                sanitization: { text: "Pre-filter: Sanitization", detail: "Clean", icon: "fa-check-circle" },
                auth: { text: "Pre-filter: Auth", detail: "SPF/DKIM Pass (Gmail)", icon: "fa-check-circle" },
                attach: { text: "Pre-filter: Attachment Intel", detail: "No Attachments", icon: "fa-minus-circle" },
                behavior: { text: "Core: Behavioral Analysis", detail: "Anomaly: CEO using Gmail", icon: "fa-times-circle" },
                nlp: { text: "Core: ML & NLP Pipelines", detail: "Urgency, Secrecy, Financial Req", icon: "fa-times-circle" }
            },
            xai: "While the email passes basic authentication, behavioral analysis flags a severe anomaly: the CEO is using a personal Gmail account for a financial request. The NLP model detected a classic Business Email Compromise (BEC) pattern involving secrecy and urgency."
        }
    },
    {
        id: 4,
        senderName: "IT Support",
        senderAddress: "it-helpdesk@portal-update.com",
        subject: "Required: Security Certificate Update",
        time: "Tuesday",
        preview: "Please install the latest security certificate to maintain portal access...",
        body: `<p>Attention Employee,</p><p>A critical security vulnerability has been identified. You must update your browser's security certificate immediately to maintain access to internal portals.</p><p>Please <a href="#" id="malicious-link" style="color: blue; text-decoration: underline; font-weight: bold; cursor: pointer;">click here to install the update</a>.</p><p>IT Helpdesk</p>`,
        hasAttachment: false,
        attachmentName: null,
        analysis: {
            riskLevel: "Critical",
            riskClass: "threat-critical",
            score: 95,
            desc: "Malicious link detected.",
            layers: {
                sanitization: { text: "Pre-filter: Sanitization", detail: "Clean", icon: "fa-check-circle" },
                auth: { text: "Pre-filter: Auth", detail: "Domain Spoofed", icon: "fa-times-circle" },
                attach: { text: "Pre-filter: Attachment Intel", detail: "No Attachments", icon: "fa-minus-circle" },
                behavior: { text: "Core: Behavioral Analysis", detail: "Unknown Sender Domain", icon: "fa-exclamation-triangle" },
                nlp: { text: "Core: ML & NLP Pipelines", detail: "Urgency & Embedded Link", icon: "fa-times-circle" }
            },
            xai: "The embedded link points to a known malicious domain. The NLP model detected a false sense of urgency. The sender domain 'portal-update.com' is not associated with our internal systems."
        }
    }
];

// DOM Elements
const emailListEl = document.getElementById('email-list');
const emptyStateEl = document.getElementById('empty-state');
const emailContentWrapperEl = document.getElementById('email-content-wrapper');
const fabAnalyze = document.getElementById('fab-analyze');
const analyzerOverlay = document.getElementById('analyzer-overlay');
const closeAnalyzerBtn = document.getElementById('close-analyzer');
const analyzerStatus = document.getElementById('analyzer-status');
const analyzerResults = document.getElementById('analyzer-results');

// New DOM Elements
const whitelistBtn = document.getElementById('whitelist-btn');
const blockBtn = document.getElementById('block-btn');
const reportBtn = document.getElementById('report-btn');
const fullAnalysisBtn = document.getElementById('full-analysis-btn');
const jsThreatOverlay = document.getElementById('js-threat-overlay');
const closeThreatBtn = document.getElementById('close-threat-btn');

// Full Analysis Modal elements
const fullAnalysisModal = document.getElementById('full-analysis-modal');
const famCloseBtn = document.getElementById('fam-close-btn');
const famBackdrop = document.getElementById('fam-backdrop');

// Top Risk Banner Elements
const topRiskBanner = document.getElementById('top-risk-banner');
const topRiskIcon = document.getElementById('top-risk-icon');
const topRiskText = document.getElementById('top-risk-text');
const topRiskPercentage = document.getElementById('top-risk-percentage');

let currentEmailId = null;

// Initialize
function init() {
    renderEmailList();
}

// Render Email List
function renderEmailList() {
    emailListEl.innerHTML = '';
    mockEmails.forEach(email => {
        const div = document.createElement('div');
        div.className = `email-item ${currentEmailId === email.id ? 'active' : ''}`;
        div.onclick = () => selectEmail(email.id);
        
        div.innerHTML = `
            <div class="email-item-icons">
                <i class="far fa-star"></i>
            </div>
            <div class="email-item-content">
                <div class="email-item-header">
                    <span class="email-item-sender">${email.senderName}</span>
                    <span class="email-item-time">${email.time}</span>
                </div>
                <div class="email-item-subject">${email.subject} ${email.hasAttachment ? '<i class="fas fa-paperclip" style="margin-left: 5px;"></i>' : ''}</div>
                <div class="email-item-preview">${email.preview}</div>
            </div>
        `;
        emailListEl.appendChild(div);
    });
}

// Select Email
function selectEmail(id) {
    currentEmailId = id;
    renderEmailList(); // update active class
    
    const email = mockEmails.find(e => e.id === id);
    if (!email) return;

    // Hide empty state, show content
    emptyStateEl.style.display = 'none';
    emailContentWrapperEl.style.display = 'flex';

    // Reset Top Risk Banner
    topRiskBanner.style.display = 'none';
    topRiskBanner.className = 'risk-banner';

    // Populate content
    document.getElementById('email-subject').innerText = email.subject;
    document.getElementById('email-sender-name').innerText = email.senderName;
    document.getElementById('email-sender-address').innerText = email.senderAddress;
    document.getElementById('email-time').innerText = email.time;
    document.getElementById('sender-avatar').innerText = email.senderName.charAt(0);
    document.getElementById('email-body').innerHTML = email.body;

    const attachmentsEl = document.getElementById('email-attachments');
    if (email.hasAttachment) {
        attachmentsEl.style.display = 'block';
        document.getElementById('attachment-name').innerText = email.attachmentName;
    } else {
        attachmentsEl.style.display = 'none';
    }

    // Attach listener for malicious link simulation
    const maliciousLink = document.getElementById('malicious-link');
    if (maliciousLink) {
        maliciousLink.addEventListener('click', (e) => {
            e.preventDefault();
            jsThreatOverlay.style.display = 'flex';
        });
    }

    // Show FAB, close any open analyzer
    fabAnalyze.style.display = 'flex';
    closeAnalyzer();
}

// Analyze Email Animation
fabAnalyze.addEventListener('click', () => {
    const email = mockEmails.find(e => e.id === currentEmailId);
    if (!email) return;

    // Open overlay
    analyzerOverlay.classList.add('active');
    analyzerStatus.style.display = 'flex';
    analyzerResults.style.display = 'none';
    fabAnalyze.style.display = 'none';

    // Simulate multi-layered analysis delay
    setTimeout(() => {
        populateAnalysis(email.analysis);
        analyzerStatus.style.display = 'none';
        analyzerResults.style.display = 'flex';
    }, 1500);
});

// Populate Analyzer Results
function populateAnalysis(analysis) {
    // Reset classes
    analyzerOverlay.className = `analyzer-overlay active ${analysis.riskClass}`;
    
    // Score
    document.getElementById('score-value').innerText = analysis.score;
    document.getElementById('risk-level').innerText = analysis.riskLevel;
    document.getElementById('risk-desc').innerText = analysis.desc;

    // Layers
    const layers = ['sanitization', 'auth', 'attach', 'behavior', 'nlp'];
    layers.forEach(layer => {
        const data = analysis.layers[layer];
        document.getElementById(`layer-${layer}`).innerHTML = `<i class="fas ${data.icon}"></i> ${data.text}: ${data.detail}`;
    });

    // XAI
    document.getElementById('xai-text').innerText = analysis.xai;

    // Update Top Risk Banner
    topRiskBanner.style.display = 'flex';
    topRiskBanner.className = `risk-banner ${analysis.riskClass}`;
    topRiskPercentage.innerText = `Risk Score: ${analysis.score}%`;
    
    // Buttons Visibility Logic & Top Banner Text
    if (analysis.riskLevel === 'Safe') {
        topRiskIcon.className = 'fas fa-shield-check';
        topRiskText.innerText = 'Safe - Aegis Verified';
        whitelistBtn.style.display = 'flex';
        blockBtn.style.display = 'none';
        reportBtn.style.display = 'none';
    } else if (analysis.riskLevel === 'Warning') {
        topRiskIcon.className = 'fas fa-exclamation-triangle';
        topRiskText.innerText = 'Warning - Suspicious Elements Detected';
        whitelistBtn.style.display = 'none';
        blockBtn.style.display = 'flex';
        reportBtn.style.display = 'flex';
    } else {
        topRiskIcon.className = 'fas fa-skull-crossbones';
        topRiskText.innerText = 'Critical Risk - Malware/Phishing Detected';
        whitelistBtn.style.display = 'none';
        blockBtn.style.display = 'flex';
        reportBtn.style.display = 'flex';
    }
}

// Close Analyzer
function closeAnalyzer() {
    analyzerOverlay.classList.remove('active');
    if (currentEmailId) fabAnalyze.style.display = 'flex';
    
    // reset class
    setTimeout(() => {
        analyzerOverlay.className = 'analyzer-overlay';
    }, 400);
}

closeAnalyzerBtn.addEventListener('click', closeAnalyzer);

// Whitelist Simulation
whitelistBtn.addEventListener('click', function() {
    const originalText = this.innerHTML;
    this.innerHTML = '<i class="fas fa-check"></i> Whitelisted';
    setTimeout(() => {
        this.innerHTML = originalText;
    }, 2000);
});

// Block Simulation
blockBtn.addEventListener('click', function() {
    const originalText = this.innerHTML;
    this.innerHTML = '<i class="fas fa-shield-alt"></i> Blocked';
    setTimeout(() => {
        this.innerHTML = originalText;
    }, 2000);
});

// Report False Positive Simulation
reportBtn.addEventListener('click', function() {
    const originalText = this.innerHTML;
    this.innerHTML = '<i class="fas fa-check"></i> Reported';
    setTimeout(() => {
        this.innerHTML = originalText;
    }, 2000);
});

// View Full Analysis — opens the premium Full Analysis Modal
fullAnalysisBtn.addEventListener('click', function() {
    const email = mockEmails.find(e => e.id === currentEmailId);
    if (!email) return;
    openFullAnalysisModal(email);
});

function openFullAnalysisModal(email) {
    const a = email.analysis;

    // ── Header ──────────────────────────────────────────────────
    const badge = document.getElementById('fam-risk-badge');
    badge.textContent = a.riskLevel;
    badge.className = 'fam-risk-badge';
    if (a.riskLevel === 'Safe')     badge.classList.add('badge-safe');
    else if (a.riskLevel === 'Warning') badge.classList.add('badge-warning');
    else                             badge.classList.add('badge-critical');

    document.getElementById('fam-subtitle').textContent =
        `Analyzed: ${email.subject} — ${email.time}`;

    // ── Gauge ────────────────────────────────────────────────────
    const scoreEl   = document.getElementById('fam-gauge-score');
    const labelEl   = document.getElementById('fam-gauge-label');
    const fillEl    = document.getElementById('fam-gauge-fill');
    const needleEl  = document.getElementById('fam-gauge-needle');

    scoreEl.innerHTML = `${a.score}<span>%</span>`;
    labelEl.textContent = a.riskLevel;
    labelEl.className = 'fam-gauge-label';
    if (a.riskLevel === 'Safe')     labelEl.classList.add('lbl-safe');
    else if (a.riskLevel === 'Warning') labelEl.classList.add('lbl-warning');
    else                             labelEl.classList.add('lbl-critical');

    // Arc total length ≈ 251.2 (half-circle circumference for r=80 arc)
    const arcLen = 251.2;
    const offset = arcLen - (a.score / 100) * arcLen;
    // Needle: -90° = leftmost (0%), +90° = rightmost (100%), so map score to -90..+90
    const needleDeg = -90 + (a.score / 100) * 180;

    // Reset first (re-trigger animation)
    fillEl.style.transition  = 'none';
    needleEl.style.transition = 'none';
    fillEl.style.strokeDashoffset  = arcLen;
    needleEl.style.transform = 'rotate(-90deg)';

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            fillEl.style.transition  = 'stroke-dashoffset 1.2s cubic-bezier(0.34,1.56,0.64,1)';
            needleEl.style.transition = 'transform 1.2s cubic-bezier(0.34,1.56,0.64,1)';
            fillEl.style.strokeDashoffset  = offset;
            needleEl.style.transform = `rotate(${needleDeg}deg)`;
        });
    });

    // ── Email Metadata ───────────────────────────────────────────
    document.getElementById('fam-meta-from').textContent    = `${email.senderName} <${email.senderAddress}>`;
    const domain = email.senderAddress.split('@')[1] || email.senderAddress;
    document.getElementById('fam-meta-domain').textContent  = domain;
    document.getElementById('fam-meta-subject').textContent = email.subject;
    document.getElementById('fam-meta-time').textContent    = email.time;
    document.getElementById('fam-meta-attach').textContent  = email.hasAttachment ? email.attachmentName : 'None';

    // ── XAI ─────────────────────────────────────────────────────
    document.getElementById('fam-xai-text').textContent = a.xai;

    // ── Layers ───────────────────────────────────────────────────
    const layersEl = document.getElementById('fam-layers');
    layersEl.innerHTML = '';

    const layerMap = [
        { key: 'sanitization', label: 'Pre-processing: HTML Sanitization' },
        { key: 'auth',         label: 'Layer 1: Email Auth (SPF/DKIM/DMARC)' },
        { key: 'attach',       label: 'Layer 2: Attachment Intelligence' },
        { key: 'behavior',     label: 'Layer 3: Behavioral Analysis' },
        { key: 'nlp',          label: 'Layer 4: Deep NLP Context' },
    ];

    layerMap.forEach(({ key, label }, idx) => {
        const data = a.layers[key];
        let iconClass, iconType, statusClass, statusText;

        if (data.icon === 'fa-check-circle') {
            iconClass = 'fas fa-check'; iconType = 'icon-pass';
            statusClass = 'status-pass'; statusText = 'Pass';
        } else if (data.icon === 'fa-times-circle') {
            iconClass = 'fas fa-times'; iconType = 'icon-fail';
            statusClass = 'status-fail'; statusText = 'Fail';
        } else if (data.icon === 'fa-exclamation-triangle') {
            iconClass = 'fas fa-exclamation'; iconType = 'icon-warn';
            statusClass = 'status-warn'; statusText = 'Warn';
        } else {
            iconClass = 'fas fa-minus'; iconType = 'icon-skip';
            statusClass = 'status-skip'; statusText = 'Skip';
        }

        const item = document.createElement('div');
        item.className = 'fam-layer-item';
        item.style.animationDelay = `${idx * 80}ms`;
        item.innerHTML = `
            <div class="fam-layer-icon ${iconType}"><i class="${iconClass}"></i></div>
            <div class="fam-layer-body">
                <div class="fam-layer-name">${label}</div>
                <div class="fam-layer-detail">${data.detail}</div>
            </div>
            <div class="fam-layer-status ${statusClass}">${statusText}</div>
        `;
        layersEl.appendChild(item);
    });

    // ── Threat Indicators ────────────────────────────────────────
    const indicatorsEl = document.getElementById('fam-indicators');
    indicatorsEl.innerHTML = '';

    const threatMap = {
        'fa-times-circle': { pill: 'pill-red',    icon: 'fas fa-times-circle' },
        'fa-exclamation-triangle': { pill: 'pill-yellow', icon: 'fas fa-exclamation-triangle' },
    };

    const threats = [];
    Object.values(a.layers).forEach(layer => {
        if (layer.icon === 'fa-times-circle' || layer.icon === 'fa-exclamation-triangle') {
            threats.push({ text: layer.detail, type: threatMap[layer.icon] });
        }
    });

    if (threats.length === 0) {
        indicatorsEl.innerHTML = `<div class="fam-no-threats"><i class="fas fa-check-circle"></i> No active threat indicators detected.</div>`;
    } else {
        threats.forEach((t, idx) => {
            const pill = document.createElement('div');
            pill.className = `fam-indicator-pill ${t.type.pill}`;
            pill.style.animationDelay = `${idx * 60}ms`;
            pill.innerHTML = `<i class="${t.type.icon}"></i> ${t.text}`;
            indicatorsEl.appendChild(pill);
        });
    }

    // ── Recommendation ───────────────────────────────────────────
    const recEl = document.getElementById('fam-recommendation');
    recEl.className = 'fam-recommendation';
    let recText = '';
    if (a.riskLevel === 'Safe') {
        recText = 'This email has passed all Aegis security layers and is considered safe. No action is required. You may optionally whitelist the sender to speed up future checks.';
        recEl.classList.add('rec-safe');
    } else if (a.riskLevel === 'Warning') {
        recText = 'This email contains suspicious patterns consistent with a Business Email Compromise (BEC) attempt. Exercise extreme caution — do not click links, transfer funds, or share credentials until the sender is verified through a separate channel.';
        recEl.classList.add('rec-warning');
    } else {
        recText = 'CRITICAL THREAT DETECTED. Aegis strongly recommends blocking this sender immediately and reporting this email to your IT security team. Do not open attachments, click links, or reply to this message under any circumstances.';
        recEl.classList.add('rec-critical');
    }
    recEl.textContent = recText;

    // Action buttons
    const wlBtn = document.getElementById('fam-whitelist-btn');
    const blBtn = document.getElementById('fam-block-btn');
    const rpBtn = document.getElementById('fam-report-btn');
    wlBtn.style.display = a.riskLevel === 'Safe' ? 'flex' : 'none';
    blBtn.style.display = a.riskLevel !== 'Safe' ? 'flex' : 'none';
    rpBtn.style.display = a.riskLevel !== 'Safe' ? 'flex' : 'none';

    // ── Open ─────────────────────────────────────────────────────
    fullAnalysisModal.classList.add('open');
}

function closeFullAnalysisModal() {
    fullAnalysisModal.classList.remove('open');
}

famCloseBtn.addEventListener('click', closeFullAnalysisModal);
famBackdrop.addEventListener('click', closeFullAnalysisModal);

// FAM action button feedback
document.getElementById('fam-whitelist-btn').addEventListener('click', function() {
    const orig = this.innerHTML;
    this.innerHTML = '<i class="fas fa-check"></i> Whitelisted!';
    setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
});

document.getElementById('fam-block-btn').addEventListener('click', function() {
    const orig = this.innerHTML;
    this.innerHTML = '<i class="fas fa-shield-alt"></i> Blocked!';
    setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
});

document.getElementById('fam-report-btn').addEventListener('click', function() {
    const orig = this.innerHTML;
    this.innerHTML = '<i class="fas fa-check"></i> Reported!';
    setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
});

// JS Threat Close
closeThreatBtn.addEventListener('click', () => {
    jsThreatOverlay.style.display = 'none';
});

// Run Init
init();
