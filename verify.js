// ── SHA-256 (Web Crypto API) ──────────────────────────────────

async function sha256hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── HMAC-SHA256 (Web Crypto API) ─────────────────────────────

async function hmacSha256hex(keyStr, message) {
  const enc     = new TextEncoder();
  const keyData = enc.encode(keyStr);
  const msgData = enc.encode(message);

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );

  const sig = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Main verify function ──────────────────────────────────────

async function verify() {
  const commitHash   = document.getElementById('commitHash').value.trim();
  const revealedSeed = document.getElementById('revealedSeed').value.trim();
  const numPrizes    = parseInt(document.getElementById('numPrizes').value);

  const resultsSection = document.getElementById('results');
  const resultsContent = document.getElementById('resultsContent');
  resultsContent.innerHTML = '';
  resultsSection.style.display = 'block';

  // ── Validate inputs ─────────────────────────────────────────
  if (!commitHash || !revealedSeed) {
    resultsContent.innerHTML = errorCard('Please fill in the Commit Hash and Revealed Seed.');
    return;
  }

  if (isNaN(numPrizes) || numPrizes < 1 || numPrizes > 20) {
    resultsContent.innerHTML = errorCard('Number of prizes must be between 1 and 20.');
    return;
  }

  try {
    // ── 1. Verify seed matches commit hash ──────────────────────
    const computedHash = await sha256hex(revealedSeed);
    const seedValid    = computedHash.toLowerCase() === commitHash.toLowerCase();

    let html = '';

    // Seed verification result
    html += resultBlock(
      'Seed Verification',
      `<div class="badge ${seedValid ? 'badge-green' : 'badge-red'}">
        ${seedValid ? '✅ Seed matches commit hash — draw is legitimate' : '❌ Seed does NOT match commit hash — result may have been manipulated'}
       </div>
       <div style="margin-top:14px">
         <div class="result-label">SHA-256 of revealed seed</div>
         <div class="result-value">${computedHash}</div>
       </div>
       <div style="margin-top:10px">
         <div class="result-label">Commit hash (published at raffle creation)</div>
         <div class="result-value">${commitHash}</div>
       </div>`
    );

    // ── 2. Show HMAC outputs for each prize ─────────────────────
    // These are the raw values used to pick winners — confirms the
    // draw inputs were locked in before any entries were taken.
    let hmacHtml = '';
    for (let prize = 1; prize <= numPrizes; prize++) {
      const hmac = await hmacSha256hex(revealedSeed, `draw:${prize}`);
      hmacHtml += `
        <div class="prize-card">
          <div class="prize-number">Prize ${prize}</div>
          <div style="margin-top:8px">
            <div class="result-label">HMAC-SHA256 (seed → draw:${prize})</div>
            <div class="result-value" style="word-break:break-all;font-size:0.78rem;">${hmac}</div>
          </div>
        </div>`;
    }

    html += resultBlock(
      `HMAC Derivation Outputs — ${numPrizes} prize${numPrizes !== 1 ? 's' : ''}`,
      hmacHtml
    );

    html += resultBlock(
      'What does this prove?',
      `<p style="color:var(--text-muted);font-size:0.875rem;line-height:1.7;">
        The commit hash was published in the raffle announcement <strong>before any tickets were sold</strong>.
        It is the SHA-256 hash of the secret seed. Since SHA-256 is a one-way function, the seed could not
        have been chosen after entries closed. The HMAC outputs above are the exact values used to select
        winners from the ticket list — proving the outcome was locked in from the start.
       </p>`
    );

    resultsContent.innerHTML = html;
  } catch (err) {
    resultsContent.innerHTML = errorCard('Verification failed: ' + err.message);
  }
}

// ── HTML helpers ──────────────────────────────────────────────

function resultBlock(label, content) {
  return `
    <div class="result-block">
      <div class="result-label">${label}</div>
      <div style="margin-top:8px">${content}</div>
    </div>`;
}

function errorCard(msg) {
  return `<div class="error-card">❌ ${msg.replace(/\n/g, '<br>')}</div>`;
}

// Allow Enter key to trigger verify
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') verify();
});
