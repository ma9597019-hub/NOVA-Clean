// Public values only (project URL + publishable/anon key). Never expose the secret key here.
module.exports = (req, res) => {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
  res.setHeader('Cache-Control', 'no-store');
  if (!url || !key) return res.status(500).json({ error: 'Supabase env vars missing' });
  res.status(200).json({ url, key });
};
