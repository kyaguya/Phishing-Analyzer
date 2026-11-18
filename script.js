/* ============================================================
   CyberGuard Phishing Analyzer — script.js
   Client-side heuristic & rule-based phishing detection engine.
   No external API — all analysis runs locally in the browser.
   ============================================================ */

'use strict';

// ──────────────────────────────────────────────
// SECTION 1: SAMPLE TEST CASES
// ──────────────────────────────────────────────

const SAMPLES = {
  safe: `Halo Tim,

Jadwal rapat mingguan kita untuk Jumat 22 November 2026 pukul 10.00 WIB tetap berlangsung di Ruang Konferensi A.
Agenda: Review Q4 roadmap, update sprint backlog, dan diskusi kebutuhan infrastruktur Q1 2027.

Mohon persiapkan presentasi progress masing-masing divisi. Notulensi rapat sebelumnya sudah diunggah ke Google Drive internal.

Salam,
Budi Santoso
IT Project Manager | PT Teknologi Maju
budi.santoso@teknologimaju.co.id`,

  suspicious: `Dear Nasabah Setia BCA,

Kami mendapati aktivitas yang tidak biasa pada rekening Anda. Untuk keamanan akun, silakan verifikasi identitas Anda dalam 24 jam ke depan agar akun tidak dibatasi.

Klik link berikut untuk verifikasi:
http://bca-secure-verify.xyz/akun/verifikasi

Jika Anda tidak melakukan verifikasi, akun Anda akan dibekukan secara otomatis.

Hubungi kami juga di bit.ly/bantuanBCA atau http://103.44.112.9/support

Terima kasih atas kepercayaan Anda.
Tim Layanan BCA`,

  critical: `[URGENT] Akun Anda Akan Diblokir Dalam 2 JAM!

Yth. Pelanggan Mandiri,

Kami mendeteksi percobaan login tidak sah dari lokasi asing pada akun mobile banking Anda. Demi keamanan, akun Anda akan DINONAKTIFKAN PERMANEN jika Anda tidak segera melakukan konfirmasi ulang identitas.

KLIK SEGERA: http://mandiri-secure.top/konfirmasi-akun?token=abc123

Anda HARUS memasukkan:
- Username & Password Internet Banking
- Nomor Kartu ATM
- PIN ATM Anda
- Kode OTP yang dikirim ke HP Anda
- Nomor CVV kartu kredit

Jika tidak dikonfirmasi dalam 2 JAM, dana Anda berisiko hilang. Kami tidak bertanggung jawab atas kehilangan aset digital.

Layanan Darurat: tinyurl.com/mandiri-help atau http://198.51.100.42/chat

RAHASIA - JANGAN BAGIKAN EMAIL INI
CS Mandiri Official`
};

// ──────────────────────────────────────────────
// SECTION 2: DETECTION RULES
// Each rule: { id, label, description, weight, type, patterns }
// weight: score contribution (0-100 total max)
// type  : 'url' | 'keyword' | 'credential' — controls highlight class
// ──────────────────────────────────────────────

const DETECTION_RULES = [

  // ── URL / Technical Indicators ──────────────────────
  {
    id: 'url_shortener',
    label: 'URL Shortener Terdeteksi',
    description: 'Pemendek tautan (bit.ly, tinyurl, dll.) menyembunyikan destinasi asli URL — taktik umum phishing.',
    weight: 20,
    type: 'url',
    patterns: [
      /\bbit\.ly\b/gi,
      /\btinyurl\.com\b/gi,
      /\bshorten\.me\b/gi,
      /\brebrand\.ly\b/gi,
      /\bowo\.ly\b/gi,
      /\bgoo\.gl\b/gi,
      /\bt\.co\b/gi,
      /\bshorturl\.at\b/gi,
      /\bcutt\.ly\b/gi,
      /\bqr\.ae\b/gi,
    ]
  },
  {
    id: 'ip_address_url',
    label: 'URL Berbasis IP Address',
    description: 'Tautan langsung ke IP address (mis. http://192.168.x.x/) mengindikasikan server tanpa domain resmi — ciri khas infrastruktur phishing.',
    weight: 25,
    type: 'url',
    patterns: [
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi
    ]
  },
  {
    id: 'http_non_https',
    label: 'Koneksi HTTP Tidak Terenkripsi',
    description: 'Penggunaan HTTP (bukan HTTPS) pada tautan sensitif menunjukkan tidak ada enkripsi TLS — data Anda tidak terlindungi.',
    weight: 15,
    type: 'url',
    patterns: [
      /\bhttp:\/\/(?!localhost|127\.0\.0\.1)/gi
    ]
  },
  {
    id: 'suspicious_tld',
    label: 'Domain / TLD Mencurigakan',
    description: 'TLD seperti .xyz, .top, .verify, .tk, .ml, .ga, .cf, atau subdomain yang meniru nama bank/layanan digunakan oleh pelaku phishing untuk menipu korban.',
    weight: 20,
    type: 'url',
    patterns: [
      /\b[\w-]+\.xyz\b/gi,
      /\b[\w-]+\.top\b/gi,
      /\b[\w-]+\.tk\b/gi,
      /\b[\w-]+\.ml\b/gi,
      /\b[\w-]+\.ga\b/gi,
      /\b[\w-]+\.cf\b/gi,
      /\b[\w-]+\.verify\b/gi,
      /\b[\w-]+\.secure[\w-]*\b/gi,
      /\bsecure-[\w-]+\.[a-z]{2,10}\b/gi,
      /\b(bca|mandiri|bri|bni|gopay|ovo|dana|paypal|google|microsoft|apple|amazon|netflix)[\w-]*\.[a-z]{2,10}\/\S*/gi,
    ]
  },

  // ── Social Engineering / Psychological Indicators ──────────────
  {
    id: 'urgency_threat',
    label: 'Kata Kunci Urgensi & Ancaman',
    description: 'Pesan menciptakan rasa panik (akun diblokir, batas waktu, darurat) untuk memaksa korban bertindak tanpa berpikir panjang — teknik manipulasi psikologis klasik.',
    weight: 18,
    type: 'keyword',
    patterns: [
      /\bsegera\b/gi,
      /\bdarurat\b/gi,
      /\burgent\b/gi,
      /\bpenting\b/gi,
      /\bdeadline\b/gi,
      /\batas\s+(tidak|tanpa\s+)?\s*\bbatas\b/gi,
      /\bdalam\s+\d+\s*(jam|menit|hari|detik)/gi,
      /\bakan\s+(diblokir|dibekukan|dihapus|dinonaktifkan|ditangguhkan)/gi,
      /\bblokir\b/gi,
      /\bbekukan\b/gi,
      /\bdinonaktifkan\b/gi,
      /\bterakhir\s+kali\b/gi,
      /\bhilang\s+selamanya\b/gi,
      /\bsegeralah\b/gi,
      /\btanpa\s+penundaan\b/gi,
      /\bjangan\s+terlambat\b/gi,
      /\bwaktu\s+habis\b/gi,
    ]
  },
  {
    id: 'authority_impersonation',
    label: 'Penyamaran Otoritas (Bank / Instansi)',
    description: 'Pesan mengklaim berasal dari bank, pemerintah, atau perusahaan teknologi besar untuk membangun kepercayaan palsu.',
    weight: 15,
    type: 'keyword',
    patterns: [
      /\b(tim\s+)?(bca|mandiri|bri|bni|cimb|permata|danamon|btpn|ocbc)\b/gi,
      /\b(tim\s+)?(customer\s+service|cs|layanan\s+nasabah|halo\s+bca|call\s+center)\b/gi,
      /\b(tim\s+)?(it\s+support|helpdesk|admin\s+sistem|tim\s+keamanan|security\s+team)\b/gi,
      /\b(tim\s+)?(google|microsoft|apple|meta|facebook|paypal|netflix|shopee|tokopedia|gojek|grab)\b/gi,
      /\bojk\b/gi,
      /\bkominfo\b/gi,
      /\bpolri\b/gi,
      /\bbjb\b/gi,
      /\bdirjen\b/gi,
    ]
  },
  {
    id: 'reward_bait',
    label: 'Umpan Hadiah / Cashback / Refund',
    description: 'Penawaran hadiah, undian, refund, atau cashback besar digunakan sebagai umpan agar korban mengklik tautan berbahaya.',
    weight: 12,
    type: 'keyword',
    patterns: [
      /\bmenang\b/gi,
      /\bhadiah\b/gi,
      /\bundian\b/gi,
      /\bgratifikasi\b/gi,
      /\bbonus\b/gi,
      /\bcashback\b/gi,
      /\brefund\b/gi,
      /\bpengembalian\s+dana\b/gi,
      /\bklaim\s+(hadiah|bonus|reward)\b/gi,
      /\bselamat\b.*\b(menang|terpilih|beruntung)\b/gi,
      /\bterpilih\b/gi,
      /\bgift\b/gi,
      /\bprize\b/gi,
      /\breward\b/gi,
      /\bgiveaway\b/gi,
    ]
  },
  {
    id: 'credential_request',
    label: 'Permintaan Kredensial Sensitif',
    description: 'Meminta password, PIN, OTP, CVV, atau nomor kartu adalah tanda phishing yang sangat kuat. Lembaga resmi TIDAK PERNAH meminta data ini melalui pesan/email.',
    weight: 30,
    type: 'credential',
    patterns: [
      /\bpassword\b/gi,
      /\bkata\s+sandi\b/gi,
      /\bpin\b(?!\s+(map|code|kode\s+pos))/gi,
      /\botp\b/gi,
      /\bkode\s+verifikasi\b/gi,
      /\bkode\s+otp\b/gi,
      /\bcvv\b/gi,
      /\bcvc\b/gi,
      /\bnomor\s+kartu\b/gi,
      /\bcard\s+number\b/gi,
      /\binternet\s+banking\b/gi,
      /\bmobile\s+banking\b/gi,
      /\bm-banking\b/gi,
      /\btoken\b/gi,
      /\bakun\s+(internet|mobile|m-)\b/gi,
      /\busername\b/gi,
      /\buser\s+id\b/gi,
    ]
  },
];

// ──────────────────────────────────────────────
// SECTION 3: MITIGATION RECOMMENDATIONS BY RISK LEVEL
// ──────────────────────────────────────────────

const MITIGATIONS = {
  low: [
    'Pesan ini tampak aman. Tetap waspada dan tidak terburu-buru mengklik tautan apapun.',
    'Verifikasi identitas pengirim melalui saluran resmi jika ada keraguan.',
    'Simpan nomor resmi layanan pelanggan untuk referensi langsung.',
  ],
  medium: [
    'JANGAN klik tautan apapun di pesan ini sebelum memverifikasi keasliannya.',
    'Hubungi pengirim melalui saluran resmi (bukan dari kontak di pesan ini) untuk konfirmasi.',
    'Laporkan pesan ini ke tim IT Security atau admin sistem jika diterima di lingkungan kerja.',
    'Periksa URL secara manual: ketik alamat resmi langsung di browser, jangan klik link.',
  ],
  high: [
    'JANGAN klik tautan manapun dalam pesan ini.',
    'JANGAN balas atau berinteraksi lebih lanjut dengan pengirim pesan ini.',
    'Blokir nomor / alamat email pengirim segera.',
    'Laporkan sebagai spam/phishing ke penyedia layanan email atau operator.',
    'Jika sudah mengklik: segera ganti password, aktifkan 2FA, dan pantau aktivitas akun.',
    'Laporkan ke BSSN (bssn.go.id) atau tim keamanan siber perusahaan Anda.',
  ],
  critical: [
    '🚨 INI ADALAH SERANGAN PHISHING KRITIS — HENTIKAN SEMUA INTERAKSI SEKARANG.',
    'JANGAN masukkan data apapun (password, PIN, OTP, nomor kartu) di tautan dari pesan ini.',
    'Jika sudah memberikan data: Segera hubungi bank (Halo BCA 1500888 / Mandiri 14000) untuk blokir kartu dan akun.',
    'Ganti seluruh password yang terkait SEGERA dari perangkat yang bersih.',
    'Aktifkan autentikasi dua faktor (2FA) di semua akun penting.',
    'Laporkan ke BSSN Siber melalui www.bssn.go.id atau email: incident@bssn.go.id.',
    'Simpan bukti pesan ini (screenshot) untuk keperluan pelaporan resmi.',
    'Pantau transaksi rekening selama 72 jam ke depan dan laporkan transaksi mencurigakan.',
  ]
};

// ──────────────────────────────────────────────
// SECTION 4: CORE ANALYSIS ENGINE
// ──────────────────────────────────────────────

/**
 * Runs all detection rules against the input text.
 * Returns an object with:
 *   - score        : number (0-100)
 *   - riskLevel    : 'low' | 'medium' | 'high' | 'critical'
 *   - triggeredRules: Array of rule objects that matched
 *   - matchedTerms : Map of { term -> highlight class }
 */
function analyzeText(text) {
  if (!text || text.trim().length === 0) return null;

  const triggeredRules = [];
  // Map: matched string -> css class name for highlight
  const matchedTerms = new Map();

  for (const rule of DETECTION_RULES) {
    let ruleMatched = false;

    for (const pattern of rule.patterns) {
      // Reset lastIndex for global regex
      pattern.lastIndex = 0;
      const matches = text.match(pattern);
      if (matches && matches.length > 0) {
        ruleMatched = true;
        // Collect unique matched strings for highlighting
        const cssClass = highlightClassForType(rule.type);
        for (const m of matches) {
          const key = m.trim();
          if (key) matchedTerms.set(key, cssClass);
        }
      }
    }

    if (ruleMatched) {
      triggeredRules.push(rule);
    }
  }

  // ── Score calculation ──────────────────────
  // Sum weights of triggered rules; cap at 100.
  const rawScore = triggeredRules.reduce((acc, r) => acc + r.weight, 0);
  const score = Math.min(100, rawScore);

  // ── Risk level thresholds ──────────────────
  const riskLevel = scoreToLevel(score);

  return { score, riskLevel, triggeredRules, matchedTerms };
}

/** Map rule type to CSS highlight class */
function highlightClassForType(type) {
  if (type === 'url')        return 'highlight-url';
  if (type === 'credential') return 'highlight-credential';
  return 'highlight-keyword';
}

/** Convert numeric score to risk level string */
function scoreToLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  return 'low';
}

// ──────────────────────────────────────────────
// SECTION 5: RENDERING FUNCTIONS
// ──────────────────────────────────────────────

/** Human-readable label for risk level */
const LEVEL_LABELS = {
  low:      'RENDAH — AMAN',
  medium:   'SEDANG — WASPADA',
  high:     'TINGGI — BERBAHAYA',
  critical: 'KRITIS — PHISHING'
};

const LEVEL_BADGE_CLASS = {
  low:      'badge-low',
  medium:   'badge-medium',
  high:     'badge-high',
  critical: 'badge-critical'
};

const LEVEL_SCORE_CLASS = {
  low:      'score-low',
  medium:   'score-medium',
  high:     'score-high',
  critical: 'score-critical'
};

/** Icon SVG per rule type */
function ruleTypeIcon(type) {
  if (type === 'url') {
    return `<svg class="w-4 h-4 text-red-400 red-flag-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
      <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
    </svg>`;
  }
  if (type === 'credential') {
    return `<svg class="w-4 h-4 text-yellow-400 red-flag-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
    </svg>`;
  }
  // keyword / social engineering
  return `<svg class="w-4 h-4 text-orange-400 red-flag-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
  </svg>`;
}

/**
 * Highlight builder: splits text at matched terms (via capturing-group regex),
 * escapes non-matched parts, and wraps matched parts in <mark> tags.
 */
function buildHighlightedHTMLSafe(rawText, matchedTerms) {
  if (matchedTerms.size === 0) {
    return escapeHtml(rawText);
  }

  const terms = [...matchedTerms.entries()].sort((a, b) => b[0].length - a[0].length);
  const escapedPatterns = terms.map(([term]) => escapeRegex(term));
  const combinedRegex = new RegExp(`(${escapedPatterns.join('|')})`, 'gi');

  const parts = rawText.split(combinedRegex);
  let html = '';

  for (const part of parts) {
    if (!part) continue;
    // Check if this part is a matched term
    let isMark = false;
    for (const [term, cssClass] of terms) {
      if (part.toLowerCase() === term.toLowerCase()) {
        html += `<mark class="${cssClass}">${escapeHtml(part)}</mark>`;
        isMark = true;
        break;
      }
    }
    if (!isMark) {
      html += escapeHtml(part);
    }
  }

  return html;
}

/** Escape HTML special characters */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Escape string for use inside a RegExp */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Renders the full results panel from an analysis result object.
 */
function renderResults(result, inputText) {
  const { score, riskLevel, triggeredRules, matchedTerms } = result;

  // ── Score bar ──
  const scoreBar = document.getElementById('scoreBar');
  scoreBar.className = `h-full rounded-full score-bar-transition ${LEVEL_SCORE_CLASS[riskLevel]}`;
  // Trigger animation by setting width in next frame
  requestAnimationFrame(() => {
    scoreBar.style.width = `${score}%`;
  });

  // ── Score value ──
  animateCounter('scoreValue', score);

  // ── Status badge ──
  const badge = document.getElementById('statusBadge');
  badge.className = `flex-shrink-0 self-start sm:self-center px-4 py-2 rounded-lg text-sm font-bold tracking-wide border ${LEVEL_BADGE_CLASS[riskLevel]}`;
  badge.textContent = LEVEL_LABELS[riskLevel];

  // ── Highlighted text preview ──
  const preview = document.getElementById('highlightedText');
  preview.innerHTML = buildHighlightedHTMLSafe(inputText, matchedTerms);

  // ── Red flags ──
  const list = document.getElementById('redFlagsList');
  list.innerHTML = '';

  if (triggeredRules.length === 0) {
    list.innerHTML = `<li class="text-sm text-slate-500 italic py-2 text-center">Tidak ada indikator berbahaya yang terdeteksi.</li>`;
  } else {
    for (const rule of triggeredRules) {
      const li = document.createElement('li');
      li.className = 'red-flag-item fade-in';
      li.innerHTML = `
        ${ruleTypeIcon(rule.type)}
        <div>
          <div class="red-flag-label ${LEVEL_FLAG_COLOR_CLASS[riskLevel]}">${escapeHtml(rule.label)}</div>
          <div class="red-flag-desc">${escapeHtml(rule.description)}</div>
        </div>`;
      list.appendChild(li);
    }
  }

  // ── Mitigations ──
  const mitigList = document.getElementById('mitigationList');
  mitigList.innerHTML = '';
  const mitigations = MITIGATIONS[riskLevel] || [];
  for (const rec of mitigations) {
    const li = document.createElement('li');
    li.className = 'mitigation-item fade-in';
    li.textContent = rec;
    mitigList.appendChild(li);
  }

  // ── Show results section ──
  const section = document.getElementById('resultsSection');
  section.classList.remove('hidden');
  section.classList.add('fade-in');
  // Smooth scroll to results
  setTimeout(() => section.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

/** Map risk level to a static Tailwind text-color class (avoid dynamic string interpolation) */
const LEVEL_FLAG_COLOR_CLASS = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-green-400',
};

/** Animates a counter from 0 to target value */
function animateCounter(elementId, target) {
  const el = document.getElementById(elementId);
  const duration = 700; // ms
  const start = performance.now();

  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    el.textContent = Math.round(progress * target);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ──────────────────────────────────────────────
// SECTION 6: HISTORY (localStorage)
// ──────────────────────────────────────────────

const HISTORY_KEY = 'cyberguard_history';
const MAX_HISTORY  = 20; // keep last N entries

/** Loads history array from localStorage */
function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
  } catch {
    return [];
  }
}

/** Saves history array to localStorage */
function saveHistory(history) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
}

/** Adds a new entry to history and re-renders */
function addToHistory(inputText, score, riskLevel) {
  const history = loadHistory();
  const entry = {
    id: Date.now(),
    timestamp: new Date().toISOString(),
    snippet: inputText.trim().substring(0, 90).replace(/\s+/g, ' '),
    score,
    riskLevel
  };
  history.unshift(entry); // newest first
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  saveHistory(history);
  renderHistory();
}

/** Removes a single history entry by id */
function deleteHistoryEntry(id) {
  const history = loadHistory().filter(e => e.id !== id);
  saveHistory(history);
  renderHistory();
}

/** Clears all history */
function clearHistory() {
  if (!confirm('Hapus seluruh riwayat analisis?')) return;
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
}

/** Formats ISO timestamp to local display string */
function formatTimestamp(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('id-ID', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

/** Score pill color classes per risk level */
const PILL_CLASSES = {
  low:      'bg-green-900/60 text-green-300 border border-green-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
};

/** Renders the history list from localStorage */
function renderHistory() {
  const history = loadHistory();
  const container = document.getElementById('historyList');
  const emptyMsg  = document.getElementById('historyEmpty');

  // Remove all existing history items (keep emptyMsg node)
  container.querySelectorAll('.history-item').forEach(el => el.remove());

  if (history.length === 0) {
    emptyMsg.style.display = '';
    return;
  }

  emptyMsg.style.display = 'none';

  for (const entry of history) {
    const div = document.createElement('div');
    div.className = 'history-item fade-in';
    div.dataset.id = entry.id;

    div.innerHTML = `
      <span class="history-score-pill ${PILL_CLASSES[entry.riskLevel]}">${entry.score}</span>
      <div class="flex-1 min-w-0">
        <div class="history-time">${formatTimestamp(entry.timestamp)}</div>
        <div class="history-snippet">${escapeHtml(entry.snippet)}${entry.snippet.length >= 90 ? '…' : ''}</div>
      </div>
      <button class="history-delete-btn" aria-label="Hapus riwayat ini" onclick="deleteHistoryEntry(${entry.id})">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>`;

    container.appendChild(div);
  }
}

// ──────────────────────────────────────────────
// SECTION 7: PUBLIC UI ACTIONS
// ──────────────────────────────────────────────

/**
 * Main function: reads input, runs analysis, renders results, saves history.
 */
function runAnalysis() {
  const inputText = document.getElementById('inputText').value;

  if (!inputText.trim()) {
    shakeTextarea();
    return;
  }

  // Show loading state briefly for UX realism
  const btn = document.getElementById('btnAnalyze');
  btn.classList.add('btn-loading');

  setTimeout(() => {
    const result = analyzeText(inputText);
    btn.classList.remove('btn-loading');

    if (!result) return;

    renderResults(result, inputText);
    addToHistory(inputText, result.score, result.riskLevel);
  }, 320);
}

/**
 * Resets the input field and hides results section.
 */
function resetAll() {
  document.getElementById('inputText').value = '';
  const section = document.getElementById('resultsSection');
  section.classList.add('hidden');
  section.classList.remove('fade-in');
  document.getElementById('scoreBar').style.width = '0%';
  document.getElementById('scoreValue').textContent = '0';
}

/**
 * Loads a sample text into the input area.
 * @param {'safe'|'suspicious'|'critical'} key
 */
function loadSample(key) {
  const text = SAMPLES[key];
  if (!text) return;
  const textarea = document.getElementById('inputText');
  textarea.value = text;
  textarea.focus();
  // Auto-run analysis after a short delay for smooth UX
  setTimeout(() => runAnalysis(), 150);
}

/**
 * Applies a brief shake animation to textarea for empty-input feedback.
 */
function shakeTextarea() {
  const ta = document.getElementById('inputText');
  ta.classList.add('border-red-500');
  ta.style.animation = 'none';
  ta.offsetHeight; // reflow
  ta.style.animation = '';
  setTimeout(() => ta.classList.remove('border-red-500'), 1000);
}

// ──────────────────────────────────────────────
// SECTION 8: KEYBOARD SHORTCUT
// ──────────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  // Ctrl+Enter or Cmd+Enter → run analysis
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    runAnalysis();
  }
});

// ──────────────────────────────────────────────
// SECTION 9: INITIALISATION
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  renderHistory();
});
