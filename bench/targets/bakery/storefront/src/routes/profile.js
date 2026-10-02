const express = require('express');

const { requireUser } = require('../middleware/auth');

const router = express.Router();

router.get('/profile', requireUser, (req, res) => {
  res.json(req.user);
});

router.patch('/profile', requireUser, (req, res) => {
  Object.assign(req.user, req.body);
  res.json(req.user);
});

router.put('/profile/address', requireUser, (req, res) => {
  const { street, city } = req.body;
  req.user.address = `${String(street || '')}, ${String(city || '')}`;
  res.json({ address: req.user.address });
});

module.exports = router;
