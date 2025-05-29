const express = require('express');
const Job = require('../models/jobs');
const { authUser, authRole } = require('../middleware/auth');

const router = express.Router();

// Post a job (Admin/SuperAdmin only)
router.post('/postjob', authUser, authRole(['admin', 'superadmin', 'employee']), async (req, res) => {
  try {
    const { title, description, company, location, salaryRange, jobType } = req.body;

    const job = new Job({
      title,
      description,
      company,
      location,
      salaryRange,
      jobType,
      postedBy: req.user._id,
    });

    await job.save();
    res.status(201).json({ message: 'Job posted successfully', job });
  } catch (err) {
    console.error('Post Job Error:', err.message);
    res.status(500).json({ error: 'Server error while posting job.' });
  }
});

// Apply to a job (User only)
router.post('/:id/apply', authUser, async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });

    if (job.applicants.includes(req.user._id)) {
      return res.status(400).json({ error: 'Already applied' });
    }

    job.applicants.push(req.user._id);
    await job.save();

    res.json({ message: 'Applied successfully' });
  } catch (err) {
    console.error('Apply Error:', err.message);
    res.status(500).json({ error: 'Server error while applying' });
  }
});

// Get all jobs based on role
router.get('/all', authUser, async (req, res) => {
  try {
    let jobs;

    if (req.user.role === 'candidate') {
      // Normal user sees all active jobs
      jobs = await Job.find({ isActive: true }).populate('postedBy', 'name email');
    } else if (req.user.role === 'admin' || req.user.role === 'employee') {
      // Admin/Employee sees only jobs they posted
      jobs = await Job.find({ isActive: true, postedBy: req.user._id }).populate('postedBy', 'name email');
    } else {
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    res.json({ jobs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load jobs' });
  }
});

// Get current user
router.get('/me', authUser, (req, res) => {
  const { name, email, role } = req.user;
  res.json({ user: { name, email, role } });
});

module.exports = router;
