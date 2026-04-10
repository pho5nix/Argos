// Argos demo — vanilla JS client.
//
// No framework, no build step. Calls the three backend endpoints and
// updates the three panes. The most interesting piece is the citation
// highlighter: clicking a key_finding in the right pane highlights the
// corresponding evidence field in the middle pane, which is the visual
// proof of the "every claim anchored to real evidence" property.

'use strict';

const DISPOSITION_BADGE_CLASS = {
  close_false_positive: 'close',
  escalate_to_case: 'escalate',
  refer_to_enhanced_due_diligence: 'edd',
  insufficient_evidence: 'insufficient',
};

const DISPOSITION_LABEL = {
  close_false_positive: 'Close — False Positive',
  escalate_to_case: 'Escalate to Case',
  refer_to_enhanced_due_diligence: 'Refer to EDD',
  insufficient_evidence: 'Insufficient Evidence',
};

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  await refreshMode();
  await loadAlerts();
});

async function refreshMode() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    const banner = document.getElementById('mode-banner');
    if (data.fallback_mode) {
      banner.textContent = 'LLM offline — fallback mode';
      banner.className = 'mode-banner fallback';
    } else {
      banner.textContent = `${data.mode} build · v${data.version}`;
      banner.className = 'mode-banner ready';
    }
  } catch (e) {
    console.error('Health check failed', e);
  }
}

async function loadAlerts() {
  const res = await fetch('/api/alerts');
  const data = await res.json();
  const list = document.getElementById('alert-list');
  list.innerHTML = '';
  for (const alert of data.alerts) {
    const li = document.createElement('li');
    li.className = 'alert-item';
    li.dataset.alertId = alert.alert_id;
    li.innerHTML = `
      <div class="alert-item-id">${alert.alert_id}</div>
      <div class="alert-item-rule">${alert.rule_id}</div>
      <div class="alert-item-meta">
        <span>${alert.customer_id} · ${alert.currency} ${alert.amount}</span>
        <span class="alert-item-score">${alert.score.toFixed(2)}</span>
      </div>
    `;
    li.addEventListener('click', () => investigate(alert.alert_id, li));
    list.appendChild(li);
  }
}

// ---------------------------------------------------------------------------
// Investigation
// ---------------------------------------------------------------------------

async function investigate(alertId, itemEl) {
  // Mark active in the list
  document.querySelectorAll('.alert-item.active').forEach(el => el.classList.remove('active'));
  itemEl.classList.add('active');

  // Show loading state
  document.getElementById('evidence-empty').classList.add('hidden');
  document.getElementById('evidence-content').classList.add('hidden');
  document.getElementById('evidence-loading').classList.remove('hidden');
  document.getElementById('recommendation-empty').classList.remove('hidden');
  document.getElementById('recommendation-content').classList.add('hidden');
  document.getElementById('loading-stage').textContent = 'Running investigation graph…';

  try {
    const res = await fetch(`/api/investigate/${alertId}`, { method: 'POST' });
    if (!res.ok) {
      throw new Error(`Investigation failed: ${res.status}`);
    }
    const data = await res.json();
    renderEvidence(data.evidence_package, data.hard_sanctions_override);
    renderRecommendation(data.recommendation, data.errors || []);
  } catch (e) {
    document.getElementById('evidence-loading').classList.add('hidden');
    document.getElementById('evidence-content').classList.remove('hidden');
    document.getElementById('evidence-content').innerHTML =
      `<div class="empty-state">Investigation error: ${e.message}</div>`;
  }
}

// ---------------------------------------------------------------------------
// Evidence rendering
// ---------------------------------------------------------------------------

function renderEvidence(pkg, sanctionsOverride) {
  document.getElementById('evidence-loading').classList.add('hidden');
  const container = document.getElementById('evidence-content');
  container.classList.remove('hidden');
  container.innerHTML = '';

  if (!pkg) {
    container.innerHTML = '<div class="empty-state">No evidence package available.</div>';
    return;
  }

  if (sanctionsOverride) {
    const banner = document.createElement('div');
    banner.className = 'evidence-section';
    banner.innerHTML = `
      <div class="evidence-section-header" style="color:var(--bad)">HARD SANCTIONS OVERRIDE</div>
      <div class="evidence-section-body">
        Primary sanctions hit detected. Reasoning LLM was bypassed entirely.
        Routed directly to human review.
      </div>
    `;
    container.appendChild(banner);
  }

  // Alert
  container.appendChild(section('alert', {
    'alert.alert_id': pkg.alert.alert_id,
    'alert.source': pkg.alert.source,
    'alert.rule_id': pkg.alert.rule_id,
    'alert.score': pkg.alert.score.toFixed(3),
    'alert.fired_at': pkg.alert.fired_at,
    'alert.rule_description': fmtUntrusted(pkg.alert.rule_description),
    'alert.customer_id': pkg.alert.customer_id,
  }));

  // Transaction
  const tx = pkg.alert.transaction;
  container.appendChild(section('alert.transaction', {
    'alert.transaction.transaction_id': tx.transaction_id,
    'alert.transaction.timestamp': tx.timestamp,
    'alert.transaction.amount': `${tx.amount} ${tx.currency}`,
    'alert.transaction.channel': tx.channel,
    'alert.transaction.originator_account': tx.originator_account,
    'alert.transaction.beneficiary_account': tx.beneficiary_account,
    'alert.transaction.beneficiary_name': fmtUntrusted(tx.beneficiary_name),
    'alert.transaction.counterparty_country': tx.counterparty_country || '(none)',
    'alert.transaction.memo': fmtUntrusted(tx.memo),
  }));

  // Customer baseline
  const b = pkg.customer_baseline;
  container.appendChild(section('customer_baseline', {
    'customer_baseline.total_transactions': b.total_transactions,
    'customer_baseline.total_volume': b.total_volume,
    'customer_baseline.avg_transaction_amount': b.avg_transaction_amount,
    'customer_baseline.median_transaction_amount': b.median_transaction_amount,
    'customer_baseline.p95_transaction_amount': b.p95_transaction_amount,
    'customer_baseline.distinct_counterparties': b.distinct_counterparties,
    'customer_baseline.distinct_countries': b.distinct_countries,
    'customer_baseline.typical_hours_utc': JSON.stringify(b.typical_hours_utc),
    'customer_baseline.typical_channels': JSON.stringify(b.typical_channels),
  }));

  // Behavioral delta
  const d = pkg.behavioral_delta;
  container.appendChild(section('behavioral_delta', {
    'behavioral_delta.amount_zscore': d.amount_zscore,
    'behavioral_delta.amount_vs_p95_ratio': d.amount_vs_p95_ratio,
    'behavioral_delta.is_new_counterparty': d.is_new_counterparty,
    'behavioral_delta.is_new_country': d.is_new_country,
    'behavioral_delta.is_out_of_hours': d.is_out_of_hours,
    'behavioral_delta.velocity_1h': d.velocity_1h,
    'behavioral_delta.velocity_24h': d.velocity_24h,
  }));

  // Sanctions
  const s = pkg.sanctions;
  container.appendChild(section('sanctions', {
    'sanctions.checked_lists': JSON.stringify(s.checked_lists),
    'sanctions.primary_hit': s.primary_hit,
    'sanctions.secondary_hit': s.secondary_hit,
    'sanctions.hit_details': JSON.stringify(s.hit_details),
  }));

  // Prior alerts
  container.appendChild(section('prior_alerts_count_90d', {
    'prior_alerts_count_90d': pkg.prior_alerts_count_90d,
  }));
}

function section(title, rows) {
  const sec = document.createElement('div');
  sec.className = 'evidence-section';
  const header = document.createElement('div');
  header.className = 'evidence-section-header';
  header.textContent = title;
  sec.appendChild(header);
  const body = document.createElement('div');
  body.className = 'evidence-section-body';
  for (const [key, value] of Object.entries(rows)) {
    const row = document.createElement('div');
    row.className = 'evidence-row';
    row.dataset.path = key;
    row.innerHTML = `
      <span class="evidence-key">${escapeHtml(key)}</span>
      <span class="evidence-value">${value}</span>
    `;
    body.appendChild(row);
  }
  sec.appendChild(body);
  return sec;
}

function fmtUntrusted(value) {
  if (value == null) return '<span style="color:var(--text-dim)">(none)</span>';
  if (typeof value === 'object' && value.content !== undefined) {
    return `<span class="untrusted-marker">&lt;UNTRUSTED origin=${escapeHtml(value.origin)}&gt;</span> <span class="untrusted-content">${escapeHtml(value.content)}</span>`;
  }
  return escapeHtml(String(value));
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Recommendation rendering
// ---------------------------------------------------------------------------

function renderRecommendation(rec, errors) {
  document.getElementById('recommendation-empty').classList.add('hidden');
  const content = document.getElementById('recommendation-content');
  content.classList.remove('hidden');

  if (!rec) {
    content.innerHTML = '<div class="empty-state">No recommendation.</div>';
    return;
  }

  // Disposition badge
  const badge = document.getElementById('disposition-badge');
  badge.textContent = DISPOSITION_LABEL[rec.disposition] || rec.disposition;
  badge.className = `disposition-badge ${DISPOSITION_BADGE_CLASS[rec.disposition] || ''}`;

  // Confidence
  const pct = Math.round(rec.confidence * 100);
  document.getElementById('confidence-fill').style.width = pct + '%';
  document.getElementById('confidence-value').textContent = `${pct}%`;

  // Key findings — each is clickable to highlight the corresponding evidence row
  const list = document.getElementById('findings-list');
  list.innerHTML = '';
  for (const finding of rec.key_findings) {
    const li = document.createElement('li');
    li.className = 'finding-item';
    li.innerHTML = `
      <div class="finding-claim">${escapeHtml(finding.claim)}</div>
      <div class="finding-path">→ ${escapeHtml(finding.evidence_path)}</div>
    `;
    li.addEventListener('click', () => highlightEvidence(finding.evidence_path));
    list.appendChild(li);
  }

  // Analyst notes
  document.getElementById('analyst-notes').textContent = rec.analyst_notes || '(none)';

  // Draft narrative
  const narrativeSection = document.getElementById('narrative-section');
  if (rec.draft_narrative) {
    narrativeSection.classList.remove('hidden');
    document.getElementById('draft-narrative').textContent = rec.draft_narrative;
  } else {
    narrativeSection.classList.add('hidden');
  }

  // Errors
  const errorsSection = document.getElementById('errors-section');
  const errorsList = document.getElementById('errors-list');
  if (errors && errors.length > 0) {
    errorsSection.classList.remove('hidden');
    errorsList.innerHTML = '';
    for (const err of errors) {
      const li = document.createElement('li');
      li.textContent = err;
      errorsList.appendChild(li);
    }
  } else {
    errorsSection.classList.add('hidden');
  }
}

function highlightEvidence(path) {
  // Clear previous highlights
  document.querySelectorAll('.evidence-row.highlight').forEach(el => el.classList.remove('highlight'));
  // Find the row with matching path (or its closest parent path)
  let target = document.querySelector(`.evidence-row[data-path="${CSS.escape(path)}"]`);
  if (!target) {
    // Try prefix match (e.g. path "alert.transaction" should highlight all alert.transaction.* rows)
    const rows = document.querySelectorAll('.evidence-row');
    for (const row of rows) {
      if (row.dataset.path && row.dataset.path.startsWith(path)) {
        row.classList.add('highlight');
      }
    }
  } else {
    target.classList.add('highlight');
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}
