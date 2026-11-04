// AI image inspection proxy. Requires a valid Supabase member session; the Anthropic key never reaches the browser.
const { createClient } = require('@supabase/supabase-js');
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const key = process.env.ANTHROPIC_API_KEY;
  const gkey = process.env.GEMINI_API_KEY;
  const qkey = process.env.GROQ_API_KEY;
  if (req.method === 'GET') return res.status(200).json({ images: !!(key || gkey || qkey) });
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!key && !gkey && !qkey) return res.status(503).json({ error: 'فحص الذكاء الاصطناعي غير مفعّل (GROQ_API_KEY غير مضبوط)' });
  const pub = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'انتهت الجلسة، سجّل الدخول من جديد' });
  const sb = createClient(process.env.SUPABASE_URL, pub, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await sb.auth.getUser(token);
  if (error || !data.user || !(data.user.app_metadata || {}).member) return res.status(401).json({ error: 'انتهت الجلسة، سجّل الدخول من جديد' });
  let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch { b = {}; } }
  const prompt = String((b && b.prompt) || '').slice(0, 6000);
  if (!prompt) return res.status(400).json({ error: 'طلب غير صالح' });
  if (qkey) {
    try {
      const c = [];
      if (b.image) c.push({ type: 'image_url', image_url: { url: 'data:' + b.media + ';base64,' + b.image } });
      c.push({ type: 'text', text: prompt });
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: 'Bearer ' + qkey },
        body: JSON.stringify({ model: process.env.GROQ_MODEL || 'qwen/qwen3.6-27b', messages: [{ role: 'user', content: c }], max_tokens: 2000, temperature: 0.1 })
      });
      const j = await r.json();
      if (!r.ok) return res.status(502).json({ error: 'فشل خدمة الفحص (Groq): ' + ((j.error && j.error.message) || r.status) });
      let text = (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '';
      text = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
      return res.status(200).json({ text });
    } catch (e) { return res.status(502).json({ error: 'تعذّر الوصول لخدمة الفحص' }); }
  }
  if (gkey) {
    try {
      const parts = [];
      if (b.image) parts.push({ inline_data: { mime_type: b.media, data: b.image } });
      parts.push({ text: prompt });
      const model = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-goog-api-key': gkey },
        body: JSON.stringify({ contents: [{ parts }], generationConfig: { maxOutputTokens: 1000 } })
      });
      const j = await r.json();
      if (!r.ok) return res.status(502).json({ error: 'فشل خدمة الفحص (Gemini): ' + ((j.error && j.error.message) || r.status) });
      const text = ((j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || []).map((x) => x.text || '').join('\n');
      return res.status(200).json({ text });
    } catch (e) { return res.status(502).json({ error: 'تعذّر الوصول لخدمة الفحص' }); }
  }
  const content = [];
  if (b.image) {
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(b.media)) return res.status(400).json({ error: 'نوع الصورة غير مقبول' });
    if (b.image.length > 4_000_000) return res.status(413).json({ error: 'الصورة كبيرة على الفحص' });
    content.push({ type: 'image', source: { type: 'base64', media_type: b.media, data: b.image } });
  }
  content.push({ type: 'text', text: prompt });
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5', max_tokens: 1000, messages: [{ role: 'user', content }] })
    });
    const j = await r.json();
    if (!r.ok) return res.status(502).json({ error: 'فشل خدمة الفحص: ' + ((j.error && j.error.message) || r.status) });
    return res.status(200).json({ text: (j.content || []).filter((x) => x.type === 'text').map((x) => x.text).join('\n') });
  } catch (e) { return res.status(502).json({ error: 'تعذّر الوصول لخدمة الفحص' }); }
};
