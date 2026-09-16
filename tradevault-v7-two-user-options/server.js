const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SECRET_KEY");
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);

const OWNER_EMAIL = "ermiyaskibatu905@gmail.com";

const ADMIN_EMAILS = new Set([
  "ermiyaskibatu12@gmail.com",
  "ermik905@gmail.com"
]);

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  SUPABASE_SECRET_KEY;

function roleForEmail(email) {
  const e = String(email || "").trim().toLowerCase();

  if (e === OWNER_EMAIL) return "owner";
  if (ADMIN_EMAILS.has(e)) return "admin";

  return "user";
}

function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    status: u.status
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return { salt, hash };
}

function verifyPassword(password, salt, expected) {
  try {
    const actual = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(actual, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    return false;
  }
}

function createSession(userId) {
  const payload = {
    id: userId,
    exp: Date.now() + (7 * 24 * 60 * 60 * 1000)
  };

  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function getUserIdFromSession(req) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) return null;

  const session = auth.slice(7);
  const parts = session.split(".");

  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;

  try {
    const expected = crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(encoded)
      .digest("base64url");

    if (signature.length !== expected.length) return null;

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (!payload.id || !payload.exp) return null;

    if (Date.now() > payload.exp) return null;

    return payload.id;
  } catch {
    return null;
  }
}

async function getUser(req) {
  const userId = getUserIdFromSession(req);

  if (!userId) return null;

  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("id", userId)
    .maybeSingle();

  if (error || !data) return null;

  const role = roleForEmail(data.email);

  if (role === "owner" || role === "admin") {
    if (
      data.role !== role ||
      data.status !== "approved"
    ) {
      const { data: updated } = await supabase
        .from("users")
        .update({
          role,
          status: "approved"
        })
        .eq("id", data.id)
        .select("*")
        .single();

      return updated || data;
    }
  }

  if (
    role === "user" &&
    data.status === "pending"
  ) {
    const created = new Date(data.created_at || Date.now());
    const age = Date.now() - created.getTime();

    if (age >= 24 * 60 * 60 * 1000) {
      const { data: updated } = await supabase
        .from("users")
        .update({
          status: "approved"
        })
        .eq("id", data.id)
        .select("*")
        .single();

      return updated || data;
    }
  }

  return data;
}

function canManageUsers(user) {
  return !!user &&
    (user.role === "owner" || user.role === "admin");
}

function send(res, status, body, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods":
      "GET,POST,PUT,DELETE,OPTIONS"
  });

  if (type === "application/json") {
    return res.end(JSON.stringify(body));
  }

  return res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";

    req.on("data", chunk => {
      raw += chunk;

      if (raw.length > 1e6) {
        req.destroy();
        reject(new Error("Request too large"));
      }
    });

    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

async function route(req, res) {
  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  const pathname = url.pathname;

  if (req.method === "OPTIONS") {
    return send(res, 204, "");
  }

  // HEALTH
  if (
    req.method === "GET" &&
    pathname === "/api/health"
  ) {
    return send(res, 200, {
      ok: true,
      service: "TradeVault",
      database: "Supabase",
      time: new Date().toISOString()
    });
  }

  // CURRENT USER
  if (
    req.method === "GET" &&
    pathname === "/api/me"
  ) {
    const user = await getUser(req);

    if (!user) {
      return send(res, 401, {
        error: "Not logged in."
      });
    }

    return send(res, 200, {
      user: publicUser(user)
    });
  }

  // SIGNUP
  if (
    req.method === "POST" &&
    pathname === "/api/signup"
  ) {
    try {
      const body = await parseBody(req);

      const name = String(body.name || "").trim();
      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const password = String(body.password || "");

      if (
        !name ||
        !email ||
        password.length < 6
      ) {
        return send(res, 400, {
          error:
            "Name, email and a password of at least 6 characters are required."
        });
      }

      const { data: existing, error: existingError } =
        await supabase
          .from("users")
          .select("id")
          .eq("email", email)
          .maybeSingle();

      if (existingError) {
        console.error(existingError);

        return send(res, 500, {
          error: "Database error while checking email."
        });
      }

      if (existing) {
        return send(res, 409, {
          error: "Email already exists."
        });
      }

      const role = roleForEmail(email);

      const hp = hashPassword(password);

      const newUser = {
        id: crypto.randomUUID(),
        name,
        email,
        password_hash: hp.hash,
        salt: hp.salt,
        role,
        status:
          role === "owner" || role === "admin"
            ? "approved"
            : "pending"
      };

      const { data: created, error } =
        await supabase
          .from("users")
          .insert(newUser)
          .select("*")
          .single();

      if (error) {
        console.error("SIGNUP DATABASE ERROR:", error);

        return send(res, 500, {
          error: "Could not create account.",
          details: error.message
        });
      }

      return send(res, 201, {
        message:
          role === "owner"
            ? "Owner account created. You can log in."
            : role === "admin"
              ? "Admin account created. You can log in."
              : "Account created. Pending for 24 hours or Owner/Admin approval.",
        status: created.status,
        role: created.role,
        instagram:
          "https://www.instagram.com/ermik905/"
      });

    } catch (err) {
      console.error("SIGNUP ERROR:", err);

      return send(res, 400, {
        error: err.message || "Invalid request."
      });
    }
  }

  // LOGIN
  if (
    req.method === "POST" &&
    pathname === "/api/login"
  ) {
    try {
      const body = await parseBody(req);

      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const password = String(body.password || "");

      if (!email || !password) {
        return send(res, 400, {
          error: "Email and password are required."
        });
      }

      const { data: user, error } =
        await supabase
          .from("users")
          .select("*")
          .eq("email", email)
          .maybeSingle();

      if (error) {
        console.error("LOGIN DATABASE ERROR:", error);

        return send(res, 500, {
          error: "Database error during login."
        });
      }

      if (!user) {
        return send(res, 401, {
          error: "Incorrect email or password."
        });
      }

      const valid = verifyPassword(
        password,
        user.salt,
        user.password_hash
      );

      if (!valid) {
        return send(res, 401, {
          error: "Incorrect email or password."
        });
      }

      let currentUser = user;

      const role = roleForEmail(user.email);

      if (
        role === "owner" ||
        role === "admin"
      ) {
        if (
          user.role !== role ||
          user.status !== "approved"
        ) {
          const { data: updated } =
            await supabase
              .from("users")
              .update({
                role,
                status: "approved"
              })
              .eq("id", user.id)
              .select("*")
              .single();

          if (updated) currentUser = updated;
        }
      }

      if (
        currentUser.role === "user" &&
        currentUser.status === "pending"
      ) {
        const created = new Date(
          currentUser.created_at || Date.now()
        );

        const age =
          Date.now() - created.getTime();

        if (
          age >= 24 * 60 * 60 * 1000
        ) {
          const { data: updated } =
            await supabase
              .from("users")
              .update({
                status: "approved"
              })
              .eq("id", currentUser.id)
              .select("*")
              .single();

          if (updated) currentUser = updated;
        }
      }

      if (currentUser.status !== "approved") {
        return send(res, 403, {
          error:
            "Your account is pending approval.",
          status: currentUser.status,
          role: currentUser.role,
          instagram:
            "https://www.instagram.com/ermik905/",
          message:
            'Send "Approve" to @ermik905 on Instagram. Your account will be approved after 24 hours or earlier by the Owner/Admin.'
        });
      }

      const session = createSession(
        currentUser.id
      );

      return send(res, 200, {
        token: session,
        user: publicUser(currentUser)
      });

    } catch (err) {
      console.error("LOGIN ERROR:", err);

      return send(res, 400, {
        error: err.message || "Invalid request."
      });
    }
  }

  // LOGOUT
  if (
    req.method === "POST" &&
    pathname === "/api/logout"
  ) {
    return send(res, 200, {
      ok: true
    });
  }

  // GET TRADES
  if (
    req.method === "GET" &&
    pathname === "/api/trades"
  ) {
    const user = await getUser(req);

    if (!user) {
      return send(res, 401, {
        error: "Login required."
      });
    }

    const mode =
      url.searchParams.get("mode") ||
      "personal";

    let query = supabase
      .from("trades")
      .select("*")
      .order("created_at", {
        ascending: false
      });

    if (mode === "shared") {
      if (user.status !== "approved") {
        return send(res, 403, {
          error: "Approval required."
        });
      }

      const { data: owner } =
        await supabase
          .from("users")
          .select("id")
          .eq("email", OWNER_EMAIL)
          .maybeSingle();

      if (!owner) {
        return send(res, 200, {
          trades: [],
          mode: "shared"
        });
      }

      query = query.eq("owner_id", owner.id);

    } else {
      if (
        user.role !== "owner" &&
        user.role !== "admin"
      ) {
        return send(res, 403, {
          error:
            "Regular users can only view Ermiyas' shared journal."
        });
      }

      query = query.eq("owner_id", user.id);
    }

    const { data, error } = await query;

    if (error) {
      console.error("TRADES GET ERROR:", error);

      return send(res, 500, {
        error: "Could not load trades."
      });
    }

    return send(res, 200, {
      trades: data || [],
      mode
    });
  }

  // CREATE TRADE
  if (
    req.method === "POST" &&
    pathname === "/api/trades"
  ) {
    const user = await getUser(req);

    if (
      !user ||
      user.status !== "approved"
    ) {
      return send(res, 403, {
        error: "Approved login required."
      });
    }

    try {
      const body = await parseBody(req);

      const trade = {
        id: crypto.randomUUID(),
        owner_id: user.id,
        date:
          body.date ||
          new Date().toISOString().slice(0, 10),
        pair: String(body.pair || ""),
        direction: String(body.direction || ""),
        entry: Number(body.entry),
        sl: Number(body.sl),
        tp: Number(body.tp),
        status:
          body.status === "LOSS"
            ? "LOSS"
            : "WIN",
        result: Number(body.result) || 0,
        rr: Number(body.rr) || 0,
        strategy: String(body.strategy || ""),
        notes: String(body.notes || "")
      };

      if (
        !trade.pair ||
        !trade.direction ||
        !Number.isFinite(trade.entry) ||
        !Number.isFinite(trade.sl) ||
        !Number.isFinite(trade.tp)
      ) {
        return send(res, 400, {
          error:
            "Pair, direction, entry, SL and TP are required."
        });
      }

      const { data, error } =
        await supabase
          .from("trades")
          .insert(trade)
          .select("*")
          .single();

      if (error) {
        console.error(
          "TRADE INSERT ERROR:",
          error
        );

        return send(res, 500, {
          error: "Could not save trade.",
          details: error.message
        });
      }

      return send(res, 201, {
        trade: data
      });

    } catch (err) {
      console.error(
        "TRADE ERROR:",
        err
      );

      return send(res, 400, {
        error:
          err.message ||
          "Invalid trade data."
      });
    }
  }

  // PENDING USERS
  if (
    req.method === "GET" &&
    pathname === "/api/users/pending"
  ) {
    const user = await getUser(req);

    if (!canManageUsers(user)) {
      return send(res, 403, {
        error:
          "Owner/Admin access required."
      });
    }

    const { data, error } =
      await supabase
        .from("users")
        .select("*")
        .eq("status", "pending")
        .order("created_at", {
          ascending: true
        });

    if (error) {
      return send(res, 500, {
        error: "Could not load pending users."
      });
    }

    return send(res, 200, {
      users: (data || []).map(publicUser)
    });
  }

  // TIP GET
  if (
    req.method === "GET" &&
    pathname === "/api/tip"
  ) {
    const user = await getUser(req);

    if (
      !user ||
      user.status !== "approved"
    ) {
      return send(res, 403, {
        error: "Approved login required."
      });
    }

    const { data, error } =
      await supabase
        .from("tips")
        .select("*")
        .eq("id", 1)
        .maybeSingle();

    if (error) {
      return send(res, 500, {
        error: "Could not load tip."
      });
    }

    return send(res, 200, {
      text: data ? data.text : ""
    });
  }

  // TIP POST
  if (
    req.method === "POST" &&
    pathname === "/api/tip"
  ) {
    const user = await getUser(req);

    if (!canManageUsers(user)) {
      return send(res, 403, {
        error:
          "Owner/Admin access required."
      });
    }

    try {
      const body = await parseBody(req);

      const text = String(
        body.text || ""
      ).slice(0, 5000);

      const { data, error } =
        await supabase
          .from("tips")
          .upsert({
            id: 1,
            text,
            updated_at:
              new Date().toISOString()
          })
          .select("*")
          .single();

      if (error) {
        return send(res, 500, {
          error: "Could not save tip.",
          details: error.message
        });
      }

      return send(res, 200, data);

    } catch (err) {
      return send(res, 400, {
        error:
          err.message || "Invalid tip."
      });
    }
  }

  // APPROVE / REJECT USER
  const approveMatch =
    pathname.match(
      /^\/api\/users\/([^/]+)\/approve$/
    );

  const rejectMatch =
    pathname.match(
      /^\/api\/users\/([^/]+)\/reject$/
    );

  if (
    req.method === "POST" &&
    (approveMatch || rejectMatch)
  ) {
    const manager = await getUser(req);

    if (!canManageUsers(manager)) {
      return send(res, 403, {
        error:
          "Owner/Admin access required."
      });
    }

    const id =
      (approveMatch || rejectMatch)[1];

    const newStatus =
      approveMatch
        ? "approved"
        : "rejected";

    const { data, error } =
      await supabase
        .from("users")
        .update({
          status: newStatus
        })
        .eq("id", id)
        .select("*")
        .maybeSingle();

    if (error) {
      return send(res, 500, {
        error: "Could not update user."
      });
    }

    if (!data) {
      return send(res, 404, {
        error: "User not found."
      });
    }

    return send(res, 200, {
      user: publicUser(data)
    });
  }

  // STATIC FRONTEND
  let file =
    pathname === "/"
      ? "/index.html"
      : pathname;

  const safe = path
    .normalize(file)
    .replace(/^(\.\.[\/\\])+/, "");

  const publicDir = path.join(
    __dirname,
    "public"
  );

  const full = path.join(
    publicDir,
    safe
  );

  if (
    !full.startsWith(publicDir)
  ) {
    return send(
      res,
      403,
      "Forbidden",
      "text/plain"
    );
  }

  if (
    fs.existsSync(full) &&
    fs.statSync(full).isFile()
  ) {
    const ext = path.extname(full);

    const types = {
      ".html":
        "text/html; charset=utf-8",
      ".css":
        "text/css; charset=utf-8",
      ".js":
        "application/javascript; charset=utf-8",
      ".json":
        "application/json; charset=utf-8",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".svg": "image/svg+xml"
    };

    return send(
      res,
      200,
      fs.readFileSync(full),
      types[ext] ||
        "application/octet-stream"
    );
  }

  return send(
    res,
    404,
    "Not found",
    "text/plain"
  );
}

const server = http.createServer(
  (req, res) => {
    route(req, res).catch(err => {
      console.error(
        "SERVER ERROR:",
        err
      );

      send(res, 500, {
        error: "Server error."
      });
    });
  }
);

server.listen(
  PORT,
  HOST,
  () => {
    console.log(
      `TradeVault running on port ${PORT}`
    );
    console.log(
      "Database: Supabase"
    );
    console.log(
      "Owner: " + OWNER_EMAIL
    );
    console.log(
      "Admins: " +
      Array.from(ADMIN_EMAILS).join(", ")
    );
  }
);
