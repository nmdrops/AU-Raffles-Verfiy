// ── SHA-256 (Web Crypto API) ──────────────────────────────────

async function sha256hex(str) {
  const data   = new TextEncoder().encode(str);
  const hash   = await crypto.subtle.digest('SHA-256', data);
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

// ── Build canonical ticket list ───────────────────────────────

function buildTicketList(entrySnapshot) {
  // Sort by discordId ascending (same as bot)
  const sorted = [...entrySnapshot].sort((a, b) => a.discordId.localeCompare(b.discordId));
  const tickets = [];
  for (const entry of sorted) {
    for (let i = 0; i < entry.tickets; i++) {
      tickets.push(entry.discordId);
    }
  }
  return { sorted, tickets };
}

// ── Fisher-Yates shuffle with seed (HMAC-based) ───────────────

async function shuffleWithSeed(seed, arr) {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const hmac = await hmacSha256hex(seed, `shuffle:${i}`);
    const j    = Number(BigInt('0x' + hmac.slice(0, 8)) % BigInt(i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

// ── Main verify function ──────────────────────────────────────

async function verify() {
  const commitHash  = document.getElementById('commitHash').value.trim();
  const revealedSeed = document.getElementById('revealedSeed').value.trim();
  const numPrizes   = parseInt(document.getElementById('numPrizes').value);
  const entryRaw    = document.getElementById('entryList').value.trim();

  const resultsSection  = document.getElementById('results');
  const resultsContent  = document.getElementById('resultsContent');
  resultsContent.innerHTML = '';
  resultsSection.style.display = 'block';

  // ── Validate inputs ───────────────────────────────────────
  if (!commitHash || !revealedSeed || !entryRaw) {
    resultsContent.innerHTML = errorCard('Please fill in all fields.');
    return;
  }

  if (isNaN(numPrizes) || numPrizes < 1 || numPrizes > 20) {
    resultsContent.innerHTML = errorCard('Number of prizes must be between 1 and 20.');
    return;
  }

  let entrySnapshot;
  try {
    entrySnapshot = JSON.parse(entryRaw);
    if (!Array.isArray(entrySnapshot)) throw new Error();
    for (const e of entrySnapshot) {
      if (typeof e.discordId !== 'string' || typeof e.tickets !== 'number' || e.tickets < 1) {
        throw new Error('Invalid entry format');
      }
    }
  } catch {
    resultsContent.innerHTML = errorCard(
      'Invalid entry list JSON. Expected format:\n' +
      '[{ "discordId": "123...", "tickets": 5 }, ...]'
    );
    return;
  }

  try {
    // ── 1. Verify seed matches commit hash ────────────────────
    const computedHash  = await sha256hex(revealedSeed);
    const seedValid     = computedHash.toLowerCase() === commitHash.toLowerCase();

    // ── 2. Build ticket list ──────────────────────────────────
    const { sorted, tickets } = buildTicketList(entrySnapshot);
    const totalTickets = tickets.length;
    const entrySnapshotStr = JSON.stringify(sorted.map(e => ({ discordId: e.discordId, tickets: e.tickets })));

    // ── 3. Derive winners ─────────────────────────────────────
    const winners = [];
    for (let prize = 1; prize <= numPrizes; prize++) {
      const message = `${entrySnapshotStr}:draw:${prize}`;
      const hmac    = await hmacSha256hex(revealedSeed, message);
      const idx     = Number(BigInt('0x' + hmac.slice(0, 8)) % BigInt(totalTickets));
      winners.push({
        prize,
        discordId:    tickets[idx],
        ticketNumber: idx + 1,
        totalTickets,
        hmac,
        message,
      });
    }

    // ── 4. Shuffle prize assignment ───────────────────────────
    const prizeLabels   = Array.from({ length: numPrizes }, (_, i) => `Prize ${i + 1}`);
    const shuffled      = numPrizes > 1 ? await shuffleWithSeed(revealedSeed, prizeLabels) : prizeLabels;
    const assignments   = winners.map((w, i) => ({ ...w, assignedPrize: shuffled[i] }));

    // ── Render results ────────────────────────────────────────
    let html = '';

    // Seed verification
    html += resultBlock(
      'Seed Verification',
      `<div class="badge ${seedValid ? 'badge-green' : 'badge-red'}">
        ${seedValid ? '✅ Seed matches commit hash' : '❌ Seed does NOT match commit hash'}
       </div>
       <div style="margin-top:10px">
         <div class="result-label">SHA-256 of revealed seed</div>
         <div class="result-value">${computedHash}</div>
       </div>
       <div style="margin-top:8px">
         <div class="result-label">Commit hash (published at creation)</div>
         <div class="result-value">${commitHash}</div>
       </div>`
    );

    // Entry list
    const entryRows = sorted.map(e =>
      `<tr><td>${e.discordId}</td><td>${e.tickets}</td></tr>`
    ).join('');

    html += resultBlock(
      `Entry List — ${totalTickets} total tickets across ${sorted.length} entrant${sorted.length !== 1 ? 's' : ''}`,
      `<table class="entry-table">
        <thead><tr><th>Discord ID</th><th>Tickets</th></tr></thead>
        <tbody>${entryRows}</tbody>
       </table>`
    );

    // Winners
    let winnerHtml = '';
    for (const w of assignments) {
      winnerHtml += `
        <div class="prize-card">
          <div class="prize-number">${w.assignedPrize}</div>
          <div style="margin-top:6px;color:#e8eaf6;font-weight:600;">Winner: <code>${w.discordId}</code></div>
          <div style="margin-top:10px">
            <div class="result-label">HMAC Input</div>
            <div class="result-value" style="word-break:break-all;font-size:0.78rem;">${w.message}</div>
          </div>
          <div style="margin-top:6px">
            <div class="result-label">HMAC-SHA256 Output</div>
            <div class="result-value" style="word-break:break-all;font-size:0.78rem;">${w.hmac}</div>
          </div>
          <div style="margin-top:6px">
            <div class="result-label">Derivation</div>
            <div class="result-value" style="font-size:0.82rem;">
              parseInt("${w.hmac.slice(0,8)}", 16) = ${parseInt(w.hmac.slice(0,8), 16)}<br>
              ${parseInt(w.hmac.slice(0,8), 16)} mod ${totalTickets} = ${Number(BigInt('0x' + w.hmac.slice(0,8)) % BigInt(totalTickets))}<br>
              → Ticket #${w.ticketNumber} of ${w.totalTickets} → <strong>${w.discordId}</strong>
            </div>
          </div>
        </div>`;
    }

    html += resultBlock('Winners', winnerHtml);

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

// Allow Enter key in single-line inputs to trigger verify
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') verify();
});
