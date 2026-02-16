const express = require("express");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { run, get, all, init } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@swdsms.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin123";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..")));

function toClientUser(row) {
  return {
    id: row.id,
    firstName: row.first_name,
    lastName: row.last_name,
    email: row.email,
    role: row.role,
    createdAt: row.created_at
  };
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(requiredRoles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) {
      res.status(401).json({ error: "Missing token" });
      return;
    }

    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (requiredRoles.length && !requiredRoles.includes(payload.role)) {
        res.status(403).json({ error: "Forbidden" });
        return;
      }
      req.user = payload;
      next();
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

app.post("/api/auth/signup", async (req, res) => {
  const { firstName, lastName, email, password, role } = req.body;

  if (!firstName || !lastName || !email || !password || !role) {
    res.status(400).json({ error: "All fields are required" });
    return;
  }

  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || password.length < 6) {
    res.status(400).json({ error: "Password does not meet requirements" });
    return;
  }

  if (!/[\w-.]+@[\w-]+\.[\w-]+/.test(email)) {
    res.status(400).json({ error: "Invalid email" });
    return;
  }

  if (!/^(student|teacher|admin)$/.test(role)) {
    res.status(400).json({ error: "Invalid role" });
    return;
  }

  try {
    const existing = await get("SELECT id FROM users WHERE email = ?", [email]);
    if (existing) {
      res.status(409).json({ error: "Email already registered" });
      return;
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await run(
      "INSERT INTO users (first_name, last_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
      [firstName.trim(), lastName.trim(), email.trim().toLowerCase(), hash, role]
    );

    const userRow = await get("SELECT * FROM users WHERE id = ?", [result.lastID]);
    const user = toClientUser(userRow);
    const token = createToken(userRow);

    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: "Email and password are required" });
    return;
  }

  try {
    const userRow = await get("SELECT * FROM users WHERE email = ?", [email.trim().toLowerCase()]);
    if (!userRow) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    if (role && role !== userRow.role) {
      res.status(403).json({ error: "Role does not match" });
      return;
    }

    const ok = await bcrypt.compare(password, userRow.password_hash);
    if (!ok) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const user = toClientUser(userRow);
    const token = createToken(userRow);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/me", auth(), async (req, res) => {
  try {
    const userRow = await get("SELECT * FROM users WHERE id = ?", [req.user.id]);
    if (!userRow) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    res.json({ user: toClientUser(userRow) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/incidents", auth(["student"]), async (req, res) => {
  const { studentName, gradeSection, incidentType, description, incidentDate } = req.body;

  if (!gradeSection || !incidentType || !description || !incidentDate) {
    res.status(400).json({ error: "All fields are required" });
    return;
  }

  try {
    const userRow = await get("SELECT first_name, last_name FROM users WHERE id = ?", [req.user.id]);
    const finalName = (studentName || "").trim() || `${userRow.first_name} ${userRow.last_name}`;

    const result = await run(
      "INSERT INTO incidents (student_id, student_name, grade_section, incident_type, description, incident_date) VALUES (?, ?, ?, ?, ?, ?)",
      [req.user.id, finalName, gradeSection.trim(), incidentType.trim(), description.trim(), incidentDate]
    );

    const row = await get("SELECT * FROM incidents WHERE id = ?", [result.lastID]);
    res.json({ incident: row });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/incidents/my", auth(["student"]), async (req, res) => {
  try {
    const rows = await all(
      "SELECT id, incident_type, description, incident_date, status FROM incidents WHERE student_id = ? ORDER BY incident_date DESC",
      [req.user.id]
    );
    res.json({ incidents: rows });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/teacher/incidents", auth(["teacher"]), async (req, res) => {
  try {
    const rows = await all(
      "SELECT student_name, grade_section, incident_type, incident_date, status FROM incidents ORDER BY incident_date DESC"
    );
    res.json({ incidents: rows });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/teacher/students", auth(["teacher"]), async (req, res) => {
  try {
    const assigned = await all(
      "SELECT student_id FROM teacher_students WHERE teacher_id = ?",
      [req.user.id]
    );

    let rows = [];
    if (assigned.length) {
      const ids = assigned.map((r) => r.student_id);
      const placeholders = ids.map(() => "?").join(",");
      rows = await all(
        `SELECT id, first_name, last_name, email, created_at FROM users WHERE role = 'student' AND id IN (${placeholders}) ORDER BY created_at DESC`,
        ids
      );
    } else {
      rows = await all(
        "SELECT id, first_name, last_name, email, created_at FROM users WHERE role = 'student' ORDER BY created_at DESC"
      );
    }

    res.json({ students: rows });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/stats", auth(["admin"]), async (req, res) => {
  try {
    const totalUsers = await get("SELECT COUNT(*) AS count FROM users");
    const students = await get("SELECT COUNT(*) AS count FROM users WHERE role = 'student'");
    const teachers = await get("SELECT COUNT(*) AS count FROM users WHERE role = 'teacher'");
    const admins = await get("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'");

    const incidentStats = await get(
      "SELECT " +
        "COUNT(*) AS total," +
        "SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending," +
        "SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS resolved " +
      "FROM incidents"
    );

    res.json({
      users: {
        total: totalUsers.count,
        students: students.count,
        teachers: teachers.count,
        admins: admins.count
      },
      incidents: {
        total: incidentStats.total || 0,
        pending: incidentStats.pending || 0,
        resolved: incidentStats.resolved || 0
      }
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/users", auth(["admin"]), async (req, res) => {
  try {
    const rows = await all(
      "SELECT id, first_name, last_name, email, role, created_at FROM users ORDER BY created_at DESC"
    );
    res.json({ users: rows });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

async function ensureAdmin() {
  const existing = await get("SELECT id FROM users WHERE email = ?", [ADMIN_EMAIL]);
  if (existing) {
    return;
  }

  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  await run(
    "INSERT INTO users (first_name, last_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
    ["Admin", "User", ADMIN_EMAIL, hash, "admin"]
  );
}

async function start() {
  try {
    await init();
    await ensureAdmin();

    app.listen(PORT, () => {
      console.log(`SWDSMS backend running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start server", err);
    process.exit(1);
  }
}

start();
