const express = require('express');

const { attachUser } = require('./middleware/auth');
const reviews = require('./routes/reviews');
const media = require('./routes/media');
const profile = require('./routes/profile');
const { cakeOfTheDay } = require('./lib/specials');
const store = require('./lib/store');

const app = express();
app.use(express.json());
app.use(attachUser);

app.get('/special', (req, res) => {
  res.json(cakeOfTheDay(store.products));
});

app.use(reviews);
app.use(media);
app.use(profile);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`storefront listening on ${port}`));
