// Login bridge: identifier (phone / email / name for the two name-login accounts) + password
// -> verified against the private Supabase table "members" -> real Supabase Auth session.
// Supabase accounts stay keyed by the member's canonical NAME, so existing storage folders/data keep working.
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { OH } = require('./_users.js');

const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const same = (a, b) => { const x = Buffer.from(a || ''), y = Buffer.from(b || ''); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const slugOf = (u) => 'm' + sha(u).slice(0, 14);
const AR = '٠١٢٣٤٥٦٧٨٩';
const phoneNorm = (s) => {
  let d = String(s).replace(/[\s\-+().]/g, '').replace(/[٠-٩]/g, (c) => AR.indexOf(c));
  if (d.startsWith('0020')) d = '0' + d.slice(4); else if (d.startsWith('20') && d.length === 12) d = '0' + d.slice(2); else if (/^1\d{9}$/.test(d)) d = '0' + d;
  return d;
};
const nameNorm = (s) => String(s || '').replace(/[\s.]+/g, '').toLowerCase();
const fails = new Map(); // best-effort throttle per instance

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { SUPABASE_URL: url, SUPABASE_SECRET_KEY: secret, AUTH_BRIDGE_SECRET: bridge } = process.env;
  const pub = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
  const miss = [['SUPABASE_URL', url], ['SUPABASE_SECRET_KEY', secret], ['SUPABASE_PUBLISHABLE_KEY', pub], ['AUTH_BRIDGE_SECRET', bridge]].filter((x) => !x[1]).map((x) => x[0]);
  if (miss.length) return res.status(500).json({ error: 'متغيرات Vercel الناقصة: ' + miss.join(' ، ') });

  let body = req.body; if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  const id = String((body && body.username) || '').trim().replace(/\s+/g, ' ');
  const p = String((body && body.password) || '');
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0] || 'x';
  const f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 15 * 60e3) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 10) return res.status(429).json({ error: 'محاولات كثيرة، انتظر بضع دقائق' });
  const bad = () => { f.n++; fails.set(ip, f); return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' }); };
  if (!id || !p) return bad();

  const opt = { auth: { autoRefreshToken: false, persistSession: false } };
  const admin = createClient(url, secret, opt), anon = createClient(url, pub, opt);

  try {
    // 1) resolve the account
    let name = null, expected = null;
    if (id === 'المالك') { name = 'المالك'; expected = OH; }
    else {
      const q = await admin.from('members').select('name,phone,email,pass_hash,name_login,aliases');
      if (q.error) throw new Error('members table: ' + q.error.message);
      let hit = null;
      if (id.includes('@')) hit = q.data.find((m) => m.email && m.email.toLowerCase() === id.toLowerCase());
      else if (/^[0-9٠-٩+\s\-().]{8,}$/.test(id)) { const ph = phoneNorm(id); hit = q.data.find((m) => m.phone && phoneNorm(m.phone) === ph); }
      else { const n = nameNorm(id); hit = q.data.find((m) => m.name_login && [m.name].concat(m.aliases || []).some((a) => nameNorm(a) === n)); }
      if (hit) { name = hit.name; expected = hit.pass_hash; }
    }
    if (!name || !same(sha(p), expected)) return bad();

    // 2) Supabase Auth session (account keyed by canonical name; password derived server-side)
    const role = expected === OH ? 'owner' : 'member';
    const slug = slugOf(name), email = slug + '@members.local';
    const pw = crypto.createHmac('sha256', bridge).update('pw:' + name).digest('hex');
    const app_metadata = { member: true, role, slug };
    let r = await anon.auth.signInWithPassword({ email, password: pw });
    if (r.error) {
      const c = await admin.auth.admin.createUser({ email, password: pw, email_confirm: true, app_metadata, user_metadata: { username: name } });
      if (c.error) {
        if (!/already|registered|exists/i.test(c.error.message)) throw c.error;
        let uid = null;
        for (let page = 1; page <= 20 && !uid; page++) {
          const l = await admin.auth.admin.listUsers({ page, perPage: 200 }); if (l.error) throw l.error;
          const h = l.data.users.find((x) => x.email === email); if (h) uid = h.id; if (l.data.users.length < 200) break;
        }
        if (!uid) throw new Error('user lookup failed');
        const up = await admin.auth.admin.updateUserById(uid, { password: pw, email_confirm: true, app_metadata, user_metadata: { username: name } }); if (up.error) throw up.error;
      }
      r = await anon.auth.signInWithPassword({ email, password: pw }); if (r.error) throw r.error;
    } else if (!r.data.user.app_metadata || r.data.user.app_metadata.role !== role || r.data.user.app_metadata.slug !== slug) {
      const up = await admin.auth.admin.updateUserById(r.data.user.id, { app_metadata }); if (up.error) throw up.error;
      r = await anon.auth.signInWithPassword({ email, password: pw }); if (r.error) throw r.error;
    }
    fails.delete(ip);
    const s = r.data.session;
    return res.status(200).json({ name, slug, role, session: { access_token: s.access_token, refresh_token: s.refresh_token, expires_at: s.expires_at } });
  } catch (e) {
    console.error('login bridge error:', e && e.message);
    return res.status(500).json({ error: 'تعذّر تسجيل الدخول: ' + ((e && e.message) || 'خطأ غير معروف') });
  }
};
