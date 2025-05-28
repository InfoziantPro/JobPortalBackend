const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { authUser, authRole } = require('../middleware/auth');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EMAIL_SECRET = process.env.JWT_EMAIL_SECRET;

// Utility: Simulate sending email verification
const sendEmailVerification = async (user, token) => {
  const verificationURL = `http://localhost:5000/api/verify-email/${token}`;
  console.log(`Simulated email sent to ${user.email} with link: ${verificationURL}`);
};

// Candidate email verification endpoint
router.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, JWT_EMAIL_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) return res.status(404).json({ error: 'User not found' });

    // Remove role check; all users require verification
    user.emailVerified = true;
    await user.save();

    res.json({ message: 'Email verified successfully, you can now login.' });
  } catch (err) {
    console.error('Email Verification Error:', err);
    res.status(400).json({ error: 'Invalid or expired verification token.' });
  }
});


// Company (Admin) registration
router.post('/register/company', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const newUser = new User({ name, email, password, role: 'admin', status: 'pending' });
    await newUser.save();

    res.status(201).json({ message: 'Company registered successfully and is pending Super Admin approval.' });
  } catch (err) {
    console.error('Company Register Error:', err);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// Employee registration (only by company)
router.post('/register/employee', authUser, authRole(['admin']), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const newUser = new User({
      name,
      email,
      password,
      role: 'employee',
      status: 'pending',
      companyId: req.user._id,
    });

    await newUser.save();
    res.status(201).json({ message: 'Employee registered successfully and is pending Company approval.' });
  } catch (err) {
    console.error('Employee Register Error:', err);
    res.status(500).json({ error: 'Server error during employee registration.' });
  }
});

// Candidate registration (email verification required)
router.post('/register/candidate', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const newUser = new User({
      name,
      email,
      password,
      role: 'candidate',
      status: 'approved',
      emailVerified: false,
    });

    await newUser.save();

    const emailToken = jwt.sign({ userId: newUser._id }, JWT_EMAIL_SECRET, { expiresIn: '1d' });
    await sendEmailVerification(newUser, emailToken);

    res.status(201).json({
      message: 'Candidate registered successfully. Please verify your email to login.',
      emailVerificationLink: `http://localhost:5000/api/verify-email/${emailToken}`,
    });
  } catch (err) {
    console.error('Candidate Register Error:', err);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// Login (all users)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password.' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid email or password.' });

    // 🚫 Check email verification for ALL users
    if (!user.emailVerified) {
      const emailToken = jwt.sign({ userId: user._id }, process.env.JWT_EMAIL_SECRET, { expiresIn: '1d' });
      return res.status(403).json({
        error: 'Please verify your email before logging in.',
        emailVerified: false,
        emailVerificationLink: `http://localhost:5000/api/verify-email/${emailToken}`
      });
    }

    // 🚫 Restrict admin login if not approved
    if (user.role === 'admin' && user.status !== 'approved') {
      return res.status(403).json({
        error: 'Your company registration is pending Super Admin approval.',
        status: user.status
      });
    }

    // ✅ All checks passed - create token
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        status: user.status
      }
    });

  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ error: 'Server error during login.' });
  }
});


// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// Super Admin: Approve Company
router.post('/approve/company/:companyId', authUser, authRole(['superadmin']), async (req, res) => {
  try {
    const company = await User.findById(req.params.companyId);
    if (!company || company.role !== 'admin') return res.status(404).json({ error: 'Company not found' });

    company.status = 'approved';
    company.approvedBy = req.user._id;
    await company.save();

    res.json({ message: 'Company approved successfully.' });
  } catch (err) {
    console.error('Company Approval Error:', err);
    res.status(500).json({ error: 'Server error during company approval.' });
  }
});

// Company: Approve Employee
router.post('/approve/employee/:employeeId', authUser, authRole(['admin']), async (req, res) => {
  try {
    const employee = await User.findById(req.params.employeeId);
    if (!employee || employee.role !== 'employee' || String(employee.companyId) !== String(req.user._id)) {
      return res.status(404).json({ error: 'Employee not found or not under your company' });
    }

    employee.status = 'approved';
    employee.approvedBy = req.user._id;
    await employee.save();

    res.json({ message: 'Employee approved successfully.' });
  } catch (err) {
    console.error('Employee Approval Error:', err);
    res.status(500).json({ error: 'Server error during employee approval.' });
  }
});

// Get pending approvals (SuperAdmin for companies)
router.get('/pending/companies', authUser, authRole(['superadmin']), async (req, res) => {
  try {
    const pendingCompanies = await User.find({ role: 'admin', status: 'pending' }).select('name email createdAt');
    res.json({ pendingCompanies });
  } catch (err) {
    console.error('Get Pending Companies Error:', err);
    res.status(500).json({ error: 'Server error fetching pending companies.' });
  }
});

// Get pending employees (Company)
router.get('/pending/employees', authUser, authRole(['admin']), async (req, res) => {
  try {
    const pendingEmployees = await User.find({ role: 'employee', status: 'pending', companyId: req.user._id }).select('name email createdAt');
    res.json({ pendingEmployees });
  } catch (err) {
    console.error('Get Pending Employees Error:', err);
    res.status(500).json({ error: 'Server error fetching pending employees.' });
  }
});

const bcrypt = require('bcrypt');

// Create superadmin route (use only once, then disable or protect!)
router.post('/create-superadmin', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Basic validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    // Check if superadmin already exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Superadmin already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with role superadmin
    const superAdmin = new User({
      name,
      email,
      password, // ✅ Plain text — will be hashed automatically by the model
      role: 'superadmin',
      emailVerified: true,
      status: 'approved',
    });

    await superAdmin.save();
    res.status(201).json({ message: 'Superadmin created successfully' });
  } catch (error) {
    console.error('Superadmin creation error:', error);
    res.status(500).json({ error: 'Server error during superadmin creation' });
  }
});

module.exports = router;