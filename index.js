require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');  // <-- new import

const authRoutes = require('./routes/authRoutes');
const jobRoutes = require('./routes/jobRoutes');

const app = express();

app.use(express.json());
app.use(cookieParser());  // <-- must add to parse cookies

app.use(cors({
  origin: ['http://localhost:5173', 'https://meeyal-frontend-react.vercel.app'],
  credentials: true // <-- must allow cookies from these origins
}));

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

app.use('/api', authRoutes);
app.use('/api/jobs', jobRoutes);  // removed trailing slash, optional

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
