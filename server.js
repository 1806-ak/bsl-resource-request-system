const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Initialize SQLite Database
const db = new sqlite3.Database('requests.db');

// Initialize database tables
db.serialize(() => {
  // Admin users table
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Requests table
  db.run(`CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    department TEXT NOT NULL,
    request_type TEXT NOT NULL,
    priority TEXT NOT NULL,
    description TEXT NOT NULL,
    request_date DATE NOT NULL,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Insert default admin user (username: "Ankit Kumar", password: "123")
  const hashedPassword = bcrypt.hashSync('123', 10);
  db.run(`INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)`, 
    ['Ankit Kumar', hashedPassword]);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Admin login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM admins WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username }
    });
  });
});

// Verify token endpoint
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Get all requests
app.get('/api/requests', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM requests ORDER BY created_at DESC`, (err, requests) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(requests);
  });
});

// Create new request
app.post('/api/requests', authenticateToken, (req, res) => {
  const { department, request_type, priority, description, request_date } = req.body;

  if (!department || !request_type || !priority || !description || !request_date) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const query = `INSERT INTO requests (department, request_type, priority, description, request_date)
                 VALUES (?, ?, ?, ?, ?)`;

  db.run(query, [department, request_type, priority, description, request_date], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Return the newly created request
    db.get('SELECT * FROM requests WHERE id = ?', [this.lastID], (err, request) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({
        message: 'Request created successfully',
        request
      });
    });
  });
});

// Update request status
app.put('/api/requests/:id/status', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status || !['Pending', 'Approved', 'Rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const query = `UPDATE requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;

  db.run(query, [status, id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }

    // Return updated request
    db.get('SELECT * FROM requests WHERE id = ?', [id], (err, request) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({
        message: 'Status updated successfully',
        request
      });
    });
  });
});

// Delete request
app.delete('/api/requests/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  db.run('DELETE FROM requests WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }

    res.json({ message: 'Request deleted successfully' });
  });
});

// Get request statistics
app.get('/api/stats', authenticateToken, (req, res) => {
  const queries = {
    total: 'SELECT COUNT(*) as count FROM requests',
    pending: 'SELECT COUNT(*) as count FROM requests WHERE status = "Pending"',
    approved: 'SELECT COUNT(*) as count FROM requests WHERE status = "Approved"',
    rejected: 'SELECT COUNT(*) as count FROM requests WHERE status = "Rejected"'
  };

  const stats = {};
  let completed = 0;

  Object.keys(queries).forEach(key => {
    db.get(queries[key], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      stats[key] = result.count;
      completed++;
      
      if (completed === Object.keys(queries).length) {
        res.json(stats);
      }
    });
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Database: SQLite (requests.db)`);
  console.log(`🔐 Default admin: username="Ankit Kumar", password="123"`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('📊 Database connection closed.');
    }
    process.exit(0);
  });
});