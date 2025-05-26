const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Job = require('../models/jobs');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Admin Auth Middleware (supports both cookie and Bearer token)
const authAdmin = async (req, res, next) => {
  let token = null;

  // Try from cookie
  if (req.cookies?.token) {
    token = req.cookies.token;
  }

  // Try from header
  if (!token && req.header('Authorization')) {
    token = req.header('Authorization').replace('Bearer ', '');
  }

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admins only.' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// Admin: Add new job
router.post('/postjob', authAdmin, async (req, res) => {
  try {
    const { title, description, company, location, salaryRange, jobType } = req.body;

    if (!title || !description || !company) {
      return res.status(400).json({ error: 'Title, description, and company are required.' });
    }

    const job = new Job({
      title,
      description,
      company,
      location: location || 'Remote',
      salaryRange,
      jobType: jobType || 'Full-time',
      postedBy: req.user._id,
    });

    await job.save();
    res.status(201).json({ message: 'Job posted successfully', job });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// (Optional) Admin: Get all jobs
router.get('/all', async (req, res) => {
  try {
    const jobs = await Job.find().sort({ postedAt: -1 });
    res.json({ jobs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch jobs' });
  }
});

module.exports = router;
