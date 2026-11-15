const { createHmac } = require('node:crypto');
const { isIP } = require('node:net');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TYPES = ['Cultivation', 'Processing', 'Dispensary', 'More than one license'];
const ROOMS = ['1 to 3 rooms', '4 to 8 rooms', '9 or more rooms'];
const MAX_BYTES = 16 * 1024;

function validate(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  if (typeof body.requestId !== 'string' || !UUID.test(body.requestId)) return null;
  if (body.website !== undefined && (typeof body.website !== 'string' || body.website.trim())) return null;
  const limits = { name: 120, facility: 200, email: 254, county: 160, type: 50, rooms: 50, notes: 3000 };
  const data = {};
  for (const [key, max] of Object.entries(limits)) {
    const value = body[key] ?? '';
    if (typeof value !== 'string' || value.includes('\0')) return null;
    data[key] = value.trim();
    if (data[key].length > max) return null;
  }
  data.email = data.email.toLowerCase();
  if (!data.name || !data.facility || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) return null;
  if (!TYPES.includes(data.type) || !ROOMS.includes(data.rooms)) return null;
  return { requestId: body.requestId.toLowerCase(), data };
}

function createHandler({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    function reply(status, body) { return res.status(status).json(body); }
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return reply(405, { ok: false, error: 'Use the website booking form to submit a request.' });
    }
    const origins = new Set([
      'https://growview.app', 'https://www.growview.app', 'https://growview-2-app.vercel.app',
    ]);
    for (const host of [env.VERCEL_URL, env.VERCEL_BRANCH_URL]) {
      if (host && /^[a-zA-Z0-9.-]+\.vercel\.app$/.test(host)) origins.add(`https://${host}`);
    }
    if (!origins.has(req.headers.origin) || req.headers['sec-fetch-site'] === 'cross-site') {
      return reply(403, { ok: false, error: 'Please submit from the GrowView website.' });
    }
    if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '')) {
      return reply(415, { ok: false, error: 'Expected a JSON request.' });
    }
    let body = req.body;
    try {
      if (Number(req.headers['content-length']) > MAX_BYTES) return reply(413, { ok: false, error: 'Request is too large.' });
      const serialized = typeof body === 'string' ? body : JSON.stringify(body);
      if (!serialized || Buffer.byteLength(serialized) > MAX_BYTES) return reply(413, { ok: false, error: 'Request is too large.' });
      if (typeof body === 'string') body = JSON.parse(body);
    } catch {
      return reply(400, { ok: false, error: 'Invalid request. Please check the form and try again.' });
    }
    const input = validate(body);
    if (!input) return reply(400, { ok: false, error: 'Please check your name, facility, email, and selected options.' });

    // These variables are provided by the existing Vercel LEADS integration.
    // Never use NEXT_PUBLIC_* or the GROW connection as a secret-key fallback.
    const key = env.LEADS_SUPABASE_SERVICE_ROLE_KEY;
    let url;
    try {
      url = new URL(env.LEADS_SUPABASE_URL);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error();
      if (!key) throw new Error();
      if (!key.startsWith('sb_secret_')) {
        const claims = JSON.parse(Buffer.from(key.split('.')[1], 'base64url').toString());
        if (claims.role !== 'service_role') throw new Error();
      }
    } catch {
      return reply(503, { ok: false, error: 'Booking is temporarily unavailable. Please try again shortly.' });
    }
    // Vercel overwrites this platform header. Do not trust a caller-supplied
    // X-Forwarded-For value for the persistent abuse limit.
    const address = String(req.headers['x-vercel-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
    if (!isIP(address)) return reply(503, { ok: false, error: 'Could not confirm this request. Please try again.' });
    const requesterHash = createHmac('sha256', key).update(`website-leads:${address}`).digest('hex');
    try {
      const response = await fetchImpl(new URL('/rest/v1/rpc/submit_website_lead', url), {
        method: 'POST',
        headers: {
          apikey: key,
          ...(key.startsWith('sb_secret_') ? {} : { Authorization: `Bearer ${key}` }),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_request_id: input.requestId, p_payload: input.data, p_requester_hash: requesterHash }),
        signal: AbortSignal.timeout(12000),
      });
      if (!response.ok) throw new Error('Database rejected request');
      const result = await response.json();
      if (result?.status === 'rate_limited') {
        res.setHeader('Retry-After', '600');
        return reply(429, { ok: false, error: 'Too many requests. Please wait 10 minutes before trying again.' });
      }
      if (result?.status !== 'saved' || typeof result.id !== 'string' || !UUID.test(result.id)) throw new Error('Save not confirmed');
      return reply(201, { ok: true, id: result.id });
    } catch {
      // Do not echo database errors, request contents, or credentials.
      // A timeout may occur after a commit: retries reuse the same request ID.
      return reply(503, { ok: false, error: 'We could not confirm your request. Please retry; retrying the same request will not save it twice.' });
    }
  };
}

module.exports = createHandler();
module.exports.createHandler = createHandler;
module.exports.validate = validate;
