import express from "express";
import crypto from "crypto";
import bcrypt from "bcrypt";
import db from "../db.js";
import { apiKeyAuth } from "../middleware/apiKeyAuth.js";

const router = express.Router();

// Generate RAW API key for user (not hashed)
function generateApiKey() {
  return crypto.randomBytes(Number(process.env.API_KEY_BYTES)).toString("hex");
}

// ===============================
// 🧩 1. USER SIGNUP (username + password)
// ===============================
router.post("/signup", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: "Username & password required" });

  const hashedPassword = bcrypt.hashSync(password, 10);

  const query = "INSERT INTO users (username, password_hash) VALUES (?, ?)";

  db.query(query, [username, hashedPassword], (err) => {
    if (err) return res.status(500).json({ message: "User already exists or DB error" });

    res.json({ message: "User registered successfully" });
  });
});

// ===============================
// 🧩 2. LOGIN (creates new API KEY)
// ===============================
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: "Username & password required" });

  const query = "SELECT * FROM users WHERE username = ?";

  db.query(query, [username], (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });

    if (results.length === 0)
      return res.status(404).json({ message: "User not found" });

    const user = results[0];

    // Check password
    const validPassword = bcrypt.compareSync(password, user.password_hash);
    if (!validPassword)
      return res.status(403).json({ message: "Invalid password" });

    // Generate new API key
    const rawApiKey = generateApiKey();
    const hashedApiKey = bcrypt.hashSync(rawApiKey, 10);

    const updateQuery = "UPDATE users SET api_key_hash = ? WHERE id = ?";

    db.query(updateQuery, [hashedApiKey, user.id], (err) => {
      if (err) return res.status(500).json({ message: "DB update error" });

      res.json({
        message: "Login successful",
        apiKey: rawApiKey // return RAW key only once
      });
    });
  });
});

// ===============================
// 🧩 3. PROTECTED ROUTE USING MIDDLEWARE
// ===============================
router.get("/protected", apiKeyAuth, (req, res) => {
  res.json({
    message: "Protected data accessed ✔️",
    user: req.user.username
  });
});

export default router;
