const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const dbPath = path.join(__dirname, "swdsms.db");
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) {
        reject(err);
        return;
      }
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
  });
}

async function init() {
  await run("PRAGMA foreign_keys = ON");

  await run(
    "CREATE TABLE IF NOT EXISTS users (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT," +
      "first_name TEXT NOT NULL," +
      "last_name TEXT NOT NULL," +
      "email TEXT NOT NULL UNIQUE," +
      "password_hash TEXT NOT NULL," +
      "role TEXT NOT NULL," +
      "created_at TEXT NOT NULL DEFAULT (datetime('now'))" +
    ")"
  );

  await run(
    "CREATE TABLE IF NOT EXISTS incidents (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT," +
      "student_id INTEGER NOT NULL," +
      "student_name TEXT NOT NULL," +
      "grade_section TEXT NOT NULL," +
      "incident_type TEXT NOT NULL," +
      "description TEXT NOT NULL," +
      "incident_date TEXT NOT NULL," +
      "status TEXT NOT NULL DEFAULT 'Pending'," +
      "created_at TEXT NOT NULL DEFAULT (datetime('now'))," +
      "FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE" +
    ")"
  );

  await run(
    "CREATE TABLE IF NOT EXISTS teacher_students (" +
      "teacher_id INTEGER NOT NULL," +
      "student_id INTEGER NOT NULL," +
      "PRIMARY KEY (teacher_id, student_id)," +
      "FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE," +
      "FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE" +
    ")"
  );
}

module.exports = {
  db,
  run,
  get,
  all,
  init
};
