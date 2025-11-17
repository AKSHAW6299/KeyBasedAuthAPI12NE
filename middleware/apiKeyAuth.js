import bcrypt from "bcrypt";
import db from "../db.js";

export const apiKeyAuth = (req, res, next) => {
  const apiKey = req.header("x-api-key");
  if (!apiKey) return res.status(401).json({ message: "API key required" });

  const query = "SELECT * FROM users";

  db.query(query, (err, users) => {
    if (err) return res.status(500).json({ message: "Database error" });

    // Compare API key with hashed keys in DB
    let validUser = null;

    for (const user of users) {
      if (bcrypt.compareSync(apiKey, user.api_key_hash)) {
        validUser = user;
        break;
      }
    }

    if (!validUser)
      return res.status(403).json({ message: "Invalid API key" });

    req.user = validUser; // attach user to request
    next();
  });
};
