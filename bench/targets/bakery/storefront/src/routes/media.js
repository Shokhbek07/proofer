const express = require('express');

const { requireStaff } = require('../middleware/auth');

const router = express.Router();

const PARTNER_FEEDS = {
  flowers: 'https://feeds.partner.example/flowers.json',
  balloons: 'https://feeds.partner.example/balloons.json',
};

router.get('/partners/:name/feed', async (req, res) => {
  const url = PARTNER_FEEDS[req.params.name];
  if (!url) return res.status(404).json({ error: 'unknown partner' });
  const upstream = await fetch(url);
  res.json(await upstream.json());
});

router.post('/admin/products/:id/photo', requireStaff, async (req, res) => {
  const upstream = await fetch(req.body.url);
  const body = Buffer.from(await upstream.arrayBuffer());
  res.json({ stored: body.length, type: upstream.headers.get('content-type') });
});

module.exports = router;
