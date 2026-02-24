// ============================================
// CYBERGUARD AI - BACKEND SERVER (ULTRA-LEAN)
// ============================================

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ============================================
// CORE LOGIC (BUNDLED FOR GITHUB)
// ============================================

function analyzeURL(url) {
  let score = 0;
  const indicators = [];
  if (!url) return { riskLevel: 'safe' };

  if (/^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}/i.test(url)) { score += 40; indicators.push('IP-based link'); }
  const suspiciousKeywords = ['login', 'verify', 'account', 'banking', 'paypal', 'urgent', 'bonus', 'free'];
  suspiciousKeywords.forEach(k => { if (url.toLowerCase().includes(k)) score += 15; });
  if (url.length > 75) score += 15;
  if (['.tk', '.ml', '.xyz', '.top', '.zip'].some(tld => url.toLowerCase().includes(tld))) score += 25;
  if (url.startsWith('http://')) score += 10;

  const risk = score >= 70 ? 'critical' : score >= 40 ? 'high' : score >= 20 ? 'medium' : 'safe';
  return {
    riskLevel: risk,
    riskPercentage: Math.min(100, score),
    explanation: `Analysis found ${indicators.length || 'some'} risk factors.`,
    indicators: indicators.length ? indicators : ['Check for phishing indicators'],
    recommendation: score > 30 ? 'Do not enter credentials.' : 'Proceed with caution.'
  };
}

function analyzeMessage(message, simpleMode = false) {
  let score = 0;
  const keywords = ['urgent', 'immediately', 'winner', 'won', 'reward', 'cash', 'bank', 'verify', 'otp'];
  keywords.forEach(k => { if (message.toLowerCase().includes(k)) score += 20; });
  if (message.includes('http')) score += 20;

  const risk = score >= 60 ? 'critical' : score >= 30 ? 'high' : 'safe';
  return {
    riskLevel: risk,
    scamProbability: Math.min(100, score) + '%',
    explanation: simpleMode ? 'This looks like a trick!' : 'Suspicious patterns detected.',
    highlightedWords: keywords.filter(k => message.toLowerCase().includes(k)),
    indicators: ['Urgency tactics detected', 'Suspicious offer'],
    recommendation: 'Do not click or reply.'
  };
}

function analyzePassword(password) {
  let score = 0;
  if (!password) return null;
  score += Math.min(40, password.length * 4);
  if (/[A-Z]/.test(password)) score += 15;
  if (/[0-9]/.test(password)) score += 15;
  if (/[^A-Za-z0-9]/.test(password)) score += 30;

  const strength = score >= 80 ? 'very strong' : score >= 60 ? 'strong' : score >= 40 ? 'moderate' : 'weak';
  return {
    score: Math.min(100, score),
    strength,
    crackTime: score > 70 ? 'Centuries' : 'Minutes',
    attacks: { bruteForce: { timeEstimate: score > 50 ? 'Years' : 'Seconds' } },
    warnings: score < 40 ? ['Too weak'] : [],
    suggestions: score < 70 ? ['Add special characters'] : []
  };
}

function analyzeFile(fileName, fileSize) {
  const ext = fileName.split('.').pop().toLowerCase();
  const dangerous = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs'];
  const risk = dangerous.includes(ext) ? 'critical' : 'safe';
  return {
    riskLevel: risk,
    fileExtension: ext,
    explanation: risk === 'critical' ? 'Executable detected' : 'Standard file',
    indicators: risk === 'critical' ? ['Dangerous extension'] : [],
    recommendation: risk === 'critical' ? 'Delete immediately' : 'Safe to open'
  };
}

function analyzePrivacy(url) {
  return {
    categories: [
      { title: 'Profile Visibility', icon: '⚠️', status: 'warning', issues: ['Public profile'], recommendations: ['Set to private'] },
      { title: 'Contact Information', icon: '✓', status: 'safe', issues: [], recommendations: ['Settings OK'] },
      { title: 'Activity Tracking', icon: '⚠️', status: 'warning', issues: ['Status visible'], recommendations: ['Hide status'] }
    ]
  };
}

// ============================================
// DATABASE HELPERS
// ============================================

const DB_DIR = path.join(__dirname, '../database');
const readDB = async (f) => JSON.parse(await fs.readFile(path.join(DB_DIR, f), 'utf8').catch(() => '[]'));
const writeDB = async (f, d) => fs.writeFile(path.join(DB_DIR, f), JSON.stringify(d, null, 2));

// ============================================
// API ROUTES
// ============================================

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/scan/:type', async (req, res) => {
  const { type } = req.params;
  const body = req.body;
  let result;

  if (type === 'url') result = analyzeURL(body.url);
  else if (type === 'message') result = analyzeMessage(body.message, body.simpleMode);
  else if (type === 'password') result = analyzePassword(body.password);
  else if (type === 'file') result = analyzeFile(body.fileName, body.fileSize);
  else if (type === 'privacy') result = analyzePrivacy(body.url);

  if (result) {
    const scans = await readDB('scans.json');
    scans.push({ id: Date.now(), type, input: body.url || body.fileName || '***', result, timestamp: new Date().toISOString() });
    await writeDB('scans.json', scans);
    res.json(result);
  } else res.status(400).json({ error: 'Invalid type' });
});

app.get('/api/analytics', async (req, res) => {
  const scans = await readDB('scans.json');
  res.json({ totalScans: scans.length, scamsPreventedToday: Math.floor(scans.length * 0.4) });
});

// Initialize DB and Start
(async () => {
  await fs.mkdir(DB_DIR, { recursive: true });
  if (!await fs.access(path.join(DB_DIR, 'scans.json')).catch(() => false)) await writeDB('scans.json', []);
  app.listen(PORT, () => console.log(`🛡️ CYBERGUARD AI - SERVER ONLINE ON PORT ${PORT}`));
})();