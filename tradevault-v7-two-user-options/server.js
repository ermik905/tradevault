const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const TRADES_FILE = path.join(DATA_DIR, "trades.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
if (!fs.existsSync(TRADES_FILE)) fs.writeFileSync(TRADES_FILE, "[]");

const sessions = new Map();

const OWNER_EMAIL = "ermiyaskibatu905@gmail.com";
const ADMIN_EMAILS = new Set([
  "ermiyaskibatu12@gmail.com",
  "ermik905@gmail.com"
]);
const PRIVILEGED_EMAILS = new Set([OWNER_EMAIL, ...ADMIN_EMAILS]);

function roleForEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  if (e === OWNER_EMAIL) return "owner";
  if (ADMIN_EMAILS.has(e)) return "admin";
  return "user";
}
function normalizeUsers() {
  const users = readJson(USERS_FILE);
  let changed = false;
  for (const u of users) {
    const role = roleForEmail(u.email);
    if (role === "owner" || role === "admin") {
      if (u.role !== role || u.status !== "approved") {
        u.role = role;
        u.status = "approved";
        changed = true;
      }
    } else {
      if (u.role !== "user" || u.status === "owner") {
        u.role = "user";
        if (u.status === "owner") u.status = "pending";
        changed = true;
      }
    }
  }
  if (changed) writeJson(USERS_FILE, users);
  return users;
}
function refreshUserStatus(u) {
  if (!u) return null;
  const role = roleForEmail(u.email);
  const users = readJson(USERS_FILE);
  const stored = users.find(x => x.id === u.id);
  if (!stored) return null;
  let changed = false;
  if (role === "owner" || role === "admin") {
    if (stored.role !== role || stored.status !== "approved") {
      stored.role = role; stored.status = "approved"; changed = true;
    }
  } else if (stored.status === "pending") {
    const age = Date.now() - new Date(stored.createdAt || Date.now()).getTime();
    if (age >= 24 * 60 * 60 * 1000) {
      stored.status = "approved";
      changed = true;
    }
  }
  if (changed) writeJson(USERS_FILE, users);
  return stored;
}
function canManageUsers(u) { return !!u && (u.role === "owner" || u.role === "admin"); }

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { return []; }
}
function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, salt, expected) {
  const actual = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}
function token() { return crypto.randomBytes(32).toString("hex"); }
function send(res, status, body, type="application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*"
  });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 1e6) req.destroy();
    });
    req.on("end", () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error("Invalid JSON")); }
    });
  });
}
function getUser(req) {
  const auth = req.headers.authorization || "";
  const t = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const uid = sessions.get(t);
  if (!uid) return null;
  return refreshUserStatus(readJson(USERS_FILE).find(u => u.id === uid) || null);
}
function publicUser(u) {
  return { id:u.id, name:u.name, email:u.email, role:u.role, status:u.status };
}

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;

  if (req.method === "OPTIONS") {
    res.writeHead(204, {"Access-Control-Allow-Origin":"*", "Access-Control-Allow-Headers":"Content-Type, Authorization", "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS"});
    return res.end();
  }

  if (req.method === "GET" && pathname === "/api/health") {
    return send(res, 200, {ok:true, service:"TradeVault", time:new Date().toISOString()});
  }

  if (req.method === "GET" && pathname === "/api/me") {
    const u = getUser(req);
    if (!u) return send(res, 401, {error:"Not logged in"});
    return send(res, 200, {user: publicUser(u)});
  }

  if (req.method === "POST" && pathname === "/api/signup") {
    try {
      const body = await parseBody(req);
      const name = String(body.name || "").trim();
     const email = String(body.email || "").trim().toLowerCase();
const password = String(body.password || "");
      if (!name || !email || password.length < 6) return send(res, 400, {error:"Name, email and a password of at least 6 characters are required."});
      const users = normalizeUsers();
      if (users.some(u => u.email === email)) return send(res, 409, {error:"Email already exists."});
      const role = roleForEmail(email);
      if (users.length === 0 && role !== "owner") {
        return send(res, 400, {error:"The first account must use the Owner email: " + OWNER_EMAIL});
      }
      const hp = hashPassword(password);
      const u = {
        id: crypto.randomUUID(),
        name, email,
        salt: hp.salt, passwordHash: hp.hash,
        role,
        status: role === "owner" || role === "admin" ? "approved" : "pending",
        createdAt: new Date().toISOString()
      };
      users.push(u);
      writeJson(USERS_FILE, users);
      return send(res, 201, {
        message: role === "owner"
          ? "Owner account created. You can log in."
          : role === "admin"
            ? "Admin account created. You can log in."
            : "Account created. Pending for 24 hours or Owner/Admin approval.",
        status: u.status,
        role: u.role,
        instagram: "https://www.instagram.com/ermik905/"
      });
   } catch (err) {
  console.error("LOGIN ERROR:", err);
  return send(res, 400, {error: err.message || "Invalid request."});
}
  }

  if (req.method === "POST" && pathname === "/api/login") {
    try {
      const body = await parseBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const users = normalizeUsers();
      let u = users.find(x => x.email === email);
      if (!u || !verifyPassword(password, u.salt, u.passwordHash)) return send(res, 401, {error:"Incorrect email or password."});
      u = refreshUserStatus(u);
      if (u.status !== "approved") {
        return send(res, 403, {
          error:"Your account is pending approval.",
          status:u.status,
          role:u.role,
          instagram:"https://www.instagram.com/ermik905/",
          message:'Send "Approve" to @ermik905 on Instagram. Your account will be approved after 24 hours or earlier by the Owner/Admin.'
        });
      }
      const t = token();
      sessions.set(t, u.id);
      return send(res, 200, {token:t, user:publicUser(u)});
    } catch { return send(res, 400, {error:"Invalid request."}); }
  }

  if (req.method === "POST" && pathname === "/api/logout") {
    const auth = req.headers.authorization || "";
    const t = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    sessions.delete(t);
    return send(res, 200, {ok:true});
  }

  if (req.method === "GET" && pathname === "/api/trades") {
    const u = getUser(req);
    if (!u) return send(res, 401, {error:"Login required."});
    const mode = url.searchParams.get("mode") || "personal";
    const trades = readJson(TRADES_FILE);
    if (mode === "shared") {
      if (u.status !== "approved") return send(res, 403, {error:"Approval required."});
      return send(res, 200, {trades: trades.filter(t => t.ownerId === ownerId()), mode:"shared"});
    }
    if (u.role === "owner" || u.role === "admin") {
      return send(res, 200, {trades: trades.filter(t => t.ownerId === u.id), mode:"personal"});
    }
    return send(res, 403, {error:"Regular users can only view Ermiyas' shared journal."});
  }

  if (req.method === "POST" && pathname === "/api/trades") {
    const u = getUser(req);
    if (!u || u.status !== "approved") return send(res, 403, {error:"Approved login required."});
    try {
      const body = await parseBody(req);
      const t = {
        id: crypto.randomUUID(),
        ownerId: u.id,
        date: body.date || new Date().toISOString().slice(0,10),
        pair: String(body.pair || ""),
        direction: String(body.direction || ""),
        entry: Number(body.entry),
        sl: Number(body.sl),
        tp: Number(body.tp),
        status: body.status === "LOSS" ? "LOSS" : "WIN",
        result: Number(body.result) || 0,
        rr: Number(body.rr) || 0,
        strategy: String(body.strategy || ""),
        notes: String(body.notes || ""),
        createdAt: new Date().toISOString()
      };
      if (!t.pair || !t.direction || !Number.isFinite(t.entry) || !Number.isFinite(t.sl) || !Number.isFinite(t.tp)) {
        return send(res, 400, {error:"Pair, direction, entry, SL and TP are required."});
      }
      const trades = readJson(TRADES_FILE);
      trades.push(t);
      writeJson(TRADES_FILE, trades);
      return send(res, 201, {trade:t});
    } catch { return send(res, 400, {error:"Invalid trade data."}); }
  }

  if (req.method === "GET" && pathname === "/api/users/pending") {
    const u = getUser(req);
    if (!u || (u.role !== "owner" && u.role !== "admin")) return send(res, 403, {error:"Owner/Admin access required."});
    return send(res, 200, {users:readJson(USERS_FILE).filter(x => x.status === "pending").map(publicUser)});
  }

  if (req.method === "GET" && pathname === "/api/tip") {
    const u = getUser(req);
    if (!u || u.status !== "approved") return send(res, 403, {error:"Approved login required."});
    const file = path.join(DATA_DIR, "tip.json");
    let tip = {text:""};
    try { tip = JSON.parse(fs.readFileSync(file, "utf8")); } catch {}
    return send(res, 200, tip);
  }

  if (req.method === "POST" && pathname === "/api/tip") {
    const u = getUser(req);
    if (!u || (u.role !== "owner" && u.role !== "admin")) return send(res, 403, {error:"Owner/Admin access required."});
    try {
      const body = await parseBody(req);
      const tip = {text:String(body.text || "").slice(0,5000), updatedAt:new Date().toISOString()};
      writeJson(path.join(DATA_DIR, "tip.json"), tip);
      return send(res, 200, tip);
    } catch { return send(res, 400, {error:"Invalid tip."}); }
  }

  const approveMatch = pathname.match(/^\/api\/users\/([^/]+)\/approve$/);
  const rejectMatch = pathname.match(/^\/api\/users\/([^/]+)\/reject$/);
  if (req.method === "POST" && (approveMatch || rejectMatch)) {
    const owner = getUser(req);
    if (!canManageUsers(owner)) return send(res, 403, {error:"Owner/Admin access required."});
    const id = (approveMatch || rejectMatch)[1];
    const users = readJson(USERS_FILE);
    const target = users.find(x => x.id === id);
    if (!target) return send(res, 404, {error:"User not found."});
    target.status = approveMatch ? "approved" : "rejected";
    writeJson(USERS_FILE, users);
    return send(res, 200, {user:publicUser(target)});
  }

  // Static frontend
  let file = pathname === "/" ? "/index.html" : pathname;
  const safe = path.normalize(file).replace(/^(\.\.[\/\\])+/, "");
  const full = path.join(__dirname, "public", safe);
  if (!full.startsWith(path.join(__dirname, "public"))) return send(res, 403, "Forbidden", "text/plain");
  if (fs.existsSync(full) && fs.statSync(full).isFile()) {
    const ext = path.extname(full);
    const types = {".html":"text/html; charset=utf-8",".css":"text/css",".js":"application/javascript",".json":"application/json"};
    return send(res, 200, fs.readFileSync(full), types[ext] || "application/octet-stream");
  }
  return send(res, 404, "Not found", "text/plain");
}

function ownerId() {
  const owner = readJson(USERS_FILE).find(u => String(u.email).toLowerCase() === OWNER_EMAIL);
  return owner ? owner.id : null;
}

normalizeUsers();

http.createServer((req,res) => route(req,res).catch(() => send(res,500,{error:"Server error."}))).listen(PORT, HOST, () => {
  console.log(`TradeVault running at http://localhost:${PORT}`);
  console.log("Owner: " + OWNER_EMAIL);
  console.log("Admins: " + Array.from(ADMIN_EMAILS).join(", "));
  console.log("Regular users: pending 24h or Owner/Admin approval.");
});
