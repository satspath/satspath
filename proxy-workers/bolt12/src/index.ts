import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// Enable CORS for all routes so the SatsPath WASM client can fetch from browsers
app.use('/*', cors());

app.get('/', (c) => {
  return c.text('SatsPath BOLT12 Proxy is running.');
});

// Resolve a BOLT12 offer to a BOLT11 invoice
app.get('/resolve/:offer', async (c) => {
  const offer = c.req.param('offer');
  const amountSats = c.req.query('amount');

  if (!offer.startsWith('lno1')) {
    return c.json({ error: 'Invalid BOLT12 offer string' }, 400);
  }

  // TODO: Implement communication with a backend C-Lightning or LDK node
  // that supports fetching the invoice for the offer.
  // For the hackathon/prototype, we mock the resolution or forward to an external API.
  
  // Example dummy response matching the expected WASM parser
  return c.json({
    status: "OK",
    invoice: "lnbc1dummy_invoice_resolved_from_bolt12_offer",
    amount_sats: amountSats ? parseInt(amountSats, 10) : null
  });
});

export default app;
