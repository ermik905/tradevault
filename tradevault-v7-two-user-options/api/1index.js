const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const TRADES_FILE = path.join(DATA_DIR, "trades.json");

const sessions = new Map();

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function verifyPassword(password, salt, expected) {
  const actual = hashPassword(password, salt);
  return actual === expected;
}

function send(res, status, body) {
  res.status(status).json(body);
}

module.exports = async (req, res) => {
  if (req.method === "GET" && req.url === "/api/health") {
    return send(res, 200, {
      ok: true,
      service: "TradeVault"
    });
  }

  if (req.method === "POST" && req.url === "/api/login") {
    try {
      const { email, password } = req.body || {};

      const users = readJson(USERS_FILE);

      const user = users.find(
        u => String(u.email).toLowerCase() === String(email || "").trim().toLowerCase()
      );

      if (!user || !verifyPassword(password || "", user.salt, user.passwordHash)) {
        return send(res, 401, {
          error: "Incorrect email or password."
        });
      }

      if (user.status !== "approved") {
        return send(res, 403, {
          error: "Your account is pending approval.",
          status: user.status
        });
      }

      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, user.id);

      return send(res, 200, {
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status
        }
      });
    } catch (err) {
      console.error(err);
      return send(res, 500, {
        error: "Server error."
      });
    }
  }

  return send(res, 404, {
    error: "Not found"
  });
};
