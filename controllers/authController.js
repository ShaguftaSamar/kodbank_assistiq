const pool = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ─── REGISTER ───────────────────────────────────────────────
exports.register = async (req, res) => {
  const { uid, username, email, password, phone, role } = req.body;

  // Validation
  if (!uid || !username || !email || !password || !phone) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email format' });
  }

  if (password.length < 6) {
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
  }

  if (phone.length < 10) {
    return res.status(400).json({ success: false, message: 'Invalid phone number' });
  }

  try {
    // Check if uid or username or email already exists
    const [existing] = await pool.execute(
      'SELECT uid FROM KodUser WHERE uid = ? OR username = ? OR email = ?',
      [uid, username, email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: 'UID, username or email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user (role always customer on registration)
    await pool.execute(
      'INSERT INTO KodUser (uid, username, email, password, phone, role, balance) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [uid, username, email, hashedPassword, phone, 'customer', 100000.00]
    );

    return res.status(201).json({ success: true, message: 'Registration successful' });
  } catch (err) {
    console.error('Register error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
};

// ─── LOGIN ───────────────────────────────────────────────────
exports.login = async (req, res) => {
  const { username, password } = req.body;

  // Validation
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }

  try {
    // Fetch user
    const [users] = await pool.execute(
      'SELECT * FROM KodUser WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    const user = users[0];

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    // Generate JWT token
    const expiryDate = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours from now

    const token = jwt.sign(
      { sub: user.username, role: user.role, uid: user.uid },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Store token in DB
    await pool.execute(
      'INSERT INTO UserToken (token, uid, expairy) VALUES (?, ?, ?)',
      [token, user.uid, expiryDate]
    );

    // Set token as cookie
    res.cookie('jwt_token', token, {
      httpOnly: true,
      maxAge: 2 * 60 * 60 * 1000, // 2 hours
      sameSite: 'strict',
    });

    return res.status(200).json({ success: true, message: 'Login successful', username: user.username });
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
};

// ─── LOGOUT ──────────────────────────────────────────────────
exports.logout = async (req, res) => {
  const token = req.cookies.jwt_token;
  if (token) {
    await pool.execute('DELETE FROM UserToken WHERE token = ?', [token]);
  }
  res.clearCookie('jwt_token');
  return res.status(200).json({ success: true, message: 'Logged out successfully' });
};
