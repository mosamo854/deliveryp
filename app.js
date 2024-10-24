const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const os = require("os");
const jwt = require("jsonwebtoken"); // ติดตั้ง jsonwebtoken และนำเข้า

const app = express();
app.use(bodyParser.json());

const hostname = "42qgn.h.filess.io";
const database = "Deliveryproject_speechbare";
const dbPort = "3307"; // Database port
const username = "Deliveryproject_speechbare";
const password = "12ebeb9f079645c0118b05fd1b0950827f04ef03";
const secretKey = "your_secret_key"; // เปลี่ยนเป็น secret key ของคุณ

// สร้างการเชื่อมต่อกับฐานข้อมูล
const db = mysql.createConnection({
  host: hostname,
  user: username,
  password,
  database,
  port: dbPort,
});

db.connect(function (err) {
  if (err) throw err;
  console.log("Connected to the database!");
});

app.post('/login', async (req, res) => {
  const { phone_number, password } = req.body;

  if (!phone_number || !password) {
    return res.status(400).json({ message: 'กรุณากรอกหมายเลขโทรศัพท์และรหัสผ่าน' });
  }

  const userSql = 'SELECT user_id, name, password FROM user WHERE phone_number = ?';
  db.query(userSql, [phone_number], async (err, userResults) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (userResults.length > 0) {
      // ตรวจสอบว่าเป็นรหัสผ่านแบบ plaintext หรือไม่
      const storedPassword = userResults[0].password;

      // เทียบรหัสผ่านแบบ plaintext แทนการใช้ bcrypt
      if (password === storedPassword) {
        const token = jwt.sign(
          { id: userResults[0].user_id, role: 'user' },
          secretKey,
          { expiresIn: '1h' }
        );
        return res.status(200).json({
          message: 'Login successful!',
          token,
          user: { id: userResults[0].user_id, name: userResults[0].name, role: 'user' }
        });
      } else {
        return res.status(401).json({ message: 'หมายเลขโทรศัพท์หรือรหัสผ่านไม่ถูกต้อง' });
      }
    }

    const riderSql = 'SELECT rider_id, name, password FROM riders WHERE phone_number = ?';
    db.query(riderSql, [phone_number], async (err, riderResults) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (riderResults.length > 0) {
        const storedPassword = riderResults[0].password;

        if (password === storedPassword) {
          const token = jwt.sign(
            { id: riderResults[0].rider_id, role: 'rider' },
            secretKey,
            { expiresIn: '1h' }
          );
          return res.status(200).json({
            message: 'Login successful!',
            token,
            user: { id: riderResults[0].rider_id, name: riderResults[0].name, role: 'rider' }
          });
        } else {
          return res.status(401).json({ message: 'หมายเลขโทรศัพท์หรือรหัสผ่านไม่ถูกต้อง' });
        }
      }

      return res.status(401).json({ message: 'หมายเลขโทรศัพท์หรือรหัสผ่านไม่ถูกต้อง' });
    });
  });
});



// สมัครสมาชิกผู้ใช้ (User)
app.post('/user', async (req, res) => {
  const { phone_number, password, name, profile_picture, address, gps_location } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10); // Hash password
  const sql = 'INSERT INTO user (phone_number, password, name, profile_picture, address, gps_location) VALUES (?, ?, ?, ?, ?, POINT(?, ?))';
  db.query(sql, [phone_number, hashedPassword, name, profile_picture, address, gps_location.lat, gps_location.lng], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ message: 'User registered successfully!', userId: results.insertId });
  });
});

// สมัครสมาชิกไรเดอร์ (Rider)
app.post('/rider', async (req, res) => {
  const { phone_number, password, name, profile_picture, vehicle_registration, gps_location } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10); // Hash password
  const sql = 'INSERT INTO riders (phone_number, password, name, profile_picture, vehicle_registration, gps_location) VALUES (?, ?, ?, ?, ?, POINT(?, ?))';
  db.query(sql, [phone_number, hashedPassword, name, profile_picture, vehicle_registration, gps_location.lat, gps_location.lng], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ message: 'Rider registered successfully!', riderId: results.insertId });
  });
});

// ฟังก์ชันเพื่อดึง IP Address ของเครื่อง
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1'; // ถ้าไม่เจอ IP, ให้แสดงเป็น localhost
}

// เริ่มเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000; // Change to port 3000 for the Express server
app.listen(PORT, () => {
  const ip = getLocalIP();
  console.log(`Server is running on http://${ip}:${PORT}`);
});
