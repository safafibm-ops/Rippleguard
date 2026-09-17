const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Merges untrusted request data into a config object.
app.post('/orders', async (req, res) => {
  const defaults = { currency: 'USD', priority: 'standard' };
  const order = _.merge({}, defaults, req.body);
  const token = jwt.sign({ id: order.id }, process.env.JWT_SECRET);
  const upstream = await axios.post('https://billing.internal/charge', order, {
    headers: { authorization: `Bearer ${token}` },
  });
  res.json(upstream.data);
});

module.exports = app;
