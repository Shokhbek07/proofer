const express = require('express');

const { requireUser } = require('../middleware/auth');
const { escapeHtml } = require('../lib/specials');
const store = require('../lib/store');

const router = express.Router();

router.get('/products/:id', (req, res) => {
  const product = store.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).send('Not found');

  const items = store.reviews
    .filter((r) => r.productId === product.id)
    .map((r) => `<li><b>${escapeHtml(r.author)}</b>: ${r.text}</li>`)
    .join('');

  res.send(`<h1>${escapeHtml(product.name)}</h1><ul>${items}</ul>`);
});

router.post('/products/:id/reviews', requireUser, (req, res) => {
  store.reviews.push({
    productId: Number(req.params.id),
    author: req.user.email,
    text: String(req.body.text || ''),
  });
  res.status(201).json({ ok: true });
});

module.exports = router;
