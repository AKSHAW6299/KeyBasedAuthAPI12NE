import mysql from "mysql2";
import dotenv from "dotenv";

dotenv.config(); // MUST be at the very top


const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false // Railway needs this
  }
});

// Test database connection
db.getConnection((err, connection) => {
  if (err) {
    console.error("❌ MySQL connection error:", err);
  } else {
    console.log("✅ MySQL connected successfully!");
    connection.release();
  }
});

export default db;
