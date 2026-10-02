const jwt = require('jsonwebtoken');

const store = require('../lib/store');

const JWT_SECRET = process.env.JWT_SECRET;

function attachUser(req, res, next) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) {
    const claims = jwt.decode(header.slice(7));
    if (claims && store.users.has(claims.sub)) {
      req.user = store.users.get(claims.sub);
    }
  }
  next();
}

function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'login required' });
  next();
}

function requireStaff(req, res, next) {
  if (!req.user || req.user.role !== 'staff') {
    return res.status(403).json({ error: 'staff only' });
  }
  next();
}

function verifyWebhook(req, res, next) {
  try {
    req.webhook = jwt.verify(req.headers['x-signature'] || '', JWT_SECRET, {
      algorithms: ['HS256'],
    });
    next();
  } catch (err) {
    res.status(401).json({ error: 'bad signature' });
  }
}

module.exports = { attachUser, requireUser, requireStaff, verifyWebhook };
