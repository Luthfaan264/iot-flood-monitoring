const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection - Updated for Railway MySQL_URL
let dbConfig;

if (process.env.MYSQL_URL) {
  // Parse MySQL URL from Railway
  const url = new URL(process.env.MYSQL_URL);
  dbConfig = {
    host: url.hostname,
    user: url.username,
    password: url.password,
    database: url.pathname.substring(1),
    port: url.port || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  };
} else {
  // Fallback for local development
  dbConfig = {
    host: process.env.MYSQLHOST || 'localhost',
    user: process.env.MYSQLUSER || 'root',
    password: process.env.MYSQLPASSWORD || '',
    database: process.env.MYSQLDATABASE || 'railway',
    port: process.env.MYSQLPORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  };
}

const pool = mysql.createPool(dbConfig);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// 1. LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2. SENSOR DATA - ESP32 POST DATA
app.post('/api/sensor-data', async (req, res) => {
  try {
    const { water_level, water_flow, rain_intensity, battery_level, device_id } = req.body;
    
    // Validation
    if (water_level === undefined || water_flow === undefined || 
        rain_intensity === undefined || battery_level === undefined) {
      return res.status(400).json({ error: 'Missing sensor data' });
    }

    const [result] = await pool.execute(
      `INSERT INTO sensor_data 
       (water_level, water_flow, rain_intensity, battery_level, device_id) 
       VALUES (?, ?, ?, ?, ?)`,
      [water_level, water_flow, rain_intensity, battery_level, device_id || 'ESP32_01']
    );

    // Check for alerts
    await checkAlerts(water_level, water_flow, rain_intensity, battery_level);

    res.json({ 
      success: true, 
      message: 'Data received',
      id: result.insertId 
    });
  } catch (error) {
    console.error('Sensor data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 3. GET SENSOR DATA (Protected)
app.get('/api/sensor-data', authenticateToken, async (req, res) => {
  try {
    const { limit = 100, hours } = req.query;
    
    let query = `SELECT * FROM sensor_data ORDER BY timestamp DESC LIMIT ?`;
    let params = [parseInt(limit)];

    if (hours) {
      query = `SELECT * FROM sensor_data WHERE timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR) ORDER BY timestamp DESC`;
      params = [parseInt(hours)];
    }

    const [data] = await pool.execute(query, params);
    
    res.json(data.reverse()); // Reverse untuk chart yang proper
  } catch (error) {
    console.error('Get sensor data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 4. GET ALERTS (Protected)
app.get('/api/alerts', authenticateToken, async (req, res) => {
  try {
    const [alerts] = await pool.execute(
      'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50'
    );
    res.json(alerts);
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 5. MARK ALERT AS READ (Protected)
app.put('/api/alerts/:id/read', authenticateToken, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE alerts SET is_read = TRUE WHERE id = ?',
      [req.params.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Mark alert read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Alert checking function
async function checkAlerts(waterLevel, waterFlow, rainIntensity, batteryLevel) {
  const alerts = [];

  // Water level alert
  if (waterLevel > 50) {
    alerts.push({
      alert_type: 'banjir',
      message: `Tinggi air mencapai ${waterLevel}cm - WASPADA BANJIR!`,
      severity: 'high'
    });
  } else if (waterLevel > 30) {
    alerts.push({
      alert_type: 'banjir',
      message: `Tinggi air ${waterLevel}cm - Siaga banjir`,
      severity: 'medium'
    });
  }

  // Rain intensity alert
  if (rainIntensity > 80) {
    alerts.push({
      alert_type: 'hujan_deras',
      message: `Intensitas hujan ${rainIntensity}% - HUJAN SANGAT DERAS`,
      severity: 'high'
    });
  } else if (rainIntensity > 60) {
    alerts.push({
      alert_type: 'hujan_deras', 
      message: `Intensitas hujan ${rainIntensity}% - Hujan deras`,
      severity: 'medium'
    });
  }

  // Battery alert
  if (batteryLevel < 10) {
    alerts.push({
      alert_type: 'baterai',
      message: `Baterai ${batteryLevel}% - KRITIS! Segera charge`,
      severity: 'high'
    });
  } else if (batteryLevel < 20) {
    alerts.push({
      alert_type: 'baterai',
      message: `Baterai ${batteryLevel}% - Rendah`,
      severity: 'medium'
    });
  }

  // Insert alerts to database
  for (const alert of alerts) {
    await pool.execute(
      'INSERT INTO alerts (alert_type, message, severity) VALUES (?, ?, ?)',
      [alert.alert_type, alert.message, alert.severity]
    );
  }
}

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({ 
      status: 'OK', 
      database: 'Connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'Error', 
      database: 'Disconnected',
      error: error.message 
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Database: ${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
});
