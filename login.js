// Bridge: verifies the EXISTING password (SHA-256 hash, unchanged) then issues a real Supabase Auth session.
// Each member gets a Supabase user whose password is derived server-side (HMAC) - member passwords are never touched.
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { HP, OH } = require('./_users.js');

const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const same = (a, b) => { const x = Buffer.from(a || ''), y = Buffer.from(b || ''); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const slugOf = (u) => 'm' + sha(u).slice(0, 14);
const fails = new Map(); // best-effort throttle per instance

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { SUPABASE_URL: url, SUPABASE_SECRET_KEY: secret, AUTH_BRIDGE_SECRET: bridge } = process.env;
  const pub = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
  const miss = [['SUPABASE_URL', url], ['SUPABASE_SECRET_KEY', secret], ['SUPABASE_PUBLISHABLE_KEY', pub], ['AUTH_BRIDGE_SECRET', bridge]].filter((x) => !x[1]).map((x) => x[0]);
  if (miss.length) return res.status(500).json({ error: 'متغيرات Vercel الناقصة: ' + miss.join(' ، ') });

  let body = req.body; if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  const u = String((body && body.username) || '').trim().replace(/\s+/g, ' ');
  const p = String((body && body.password) || '');
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0] || 'x';
  const f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 15 * 60e3) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 10) return res.status(429).json({ error: 'محاولات كثيرة، انتظر بضع دقائق' });

  const expected = u === 'المالك' ? OH : HP[u];
  if (!u || !p || !expected || !same(sha(p), expected)) { f.n++; fails.set(ip, f); return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' }); }

  const role = expected === OH ? 'owner' : 'member';
  const slug = slugOf(u), email = slug + '@members.local';
  const pw = crypto.createHmac('sha256', bridge).update('pw:' + u).digest('hex');
  const app_metadata = { member: true, role, slug };
  const opt = { auth: { autoRefreshToken: false, persistSession: false } };
  const admin = createClient(url, secret, opt), anon = createClient(url, pub, opt);

  try {
    let r = await anon.auth.signInWithPassword({ email, password: pw });
    if (r.error) {
      const c = await admin.auth.admin.createUser({ email, password: pw, email_confirm: true, app_metadata, user_metadata: { username: u } });
      if (c.error) {
        if (!/already|registered|exists/i.test(c.error.message)) throw c.error;
        let id = null;
        for (let page = 1; page <= 20 && !id; page++) {
          const l = await admin.auth.admin.listUsers({ page, perPage: 200 }); if (l.error) throw l.error;
          const hit = l.data.users.find((x) => x.email === email); if (hit) id = hit.id; if (l.data.users.length < 200) break;
        }
        if (!id) throw new Error('user lookup failed');
        const up = await admin.auth.admin.updateUserById(id, { password: pw, email_confirm: true, app_metadata }); if (up.error) throw up.error;
      }
      r = await anon.auth.signInWithPassword({ email, password: pw }); if (r.error) throw r.error;
    } else if (!r.data.user.app_metadata || r.data.user.app_metadata.role !== role || r.data.user.app_metadata.slug !== slug) {
      const up = await admin.auth.admin.updateUserById(r.data.user.id, { app_metadata }); if (up.error) throw up.error;
      r = await anon.auth.signInWithPassword({ email, password: pw }); if (r.error) throw r.error;
    }
    fails.delete(ip);
    const s = r.data.session;
    return res.status(200).json({ slug, role, session: { access_token: s.access_token, refresh_token: s.refresh_token, expires_at: s.expires_at } });
  } catch (e) {
    console.error('login bridge error:', e && e.message);
    return res.status(500).json({ error: 'تعذّر إنشاء جلسة Supabase: ' + ((e && e.message) || 'خطأ غير معروف') });
  }
};
