const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/authRoutes'); // ✅ Correct

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Health check
app.get('/', (req, res) => {
  res.send('Authentication API is running...');
});

module.exports = app;
