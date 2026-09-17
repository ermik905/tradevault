const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

const OWNER_EMAIL = "ermiyaskibatu905@gmail.com";

const ADMIN_EMAILS = new Set([
  "ermiyaskibatu12@gmail.com",
  "ermik905@gmail.com"
]);

function roleForEmail(email) {
  const e = String(email || "").trim().toLowerCase();

  if (e === OWNER_EMAIL) return "owner";
  if (ADMIN_EMAILS.has(e)) return "admin";

  return "user";
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

function send(res, status, body) {
  return res.status(status).json(body);
}

module.exports = async (req, res) => {

  // HEALTH
  if (req.method === "GET" && req.url === "/api/health") {
    return send(res, 200, {
      ok: true,
      service: "TradeVault",
      database: "Supabase"
    });
  }

  // SIGNUP
  if (req.method === "POST" && req.url === "/api/signup") {
    try {
      const { name, email, password } = req.body || {};

      const cleanName = String(name || "").trim();
      const cleanEmail = String(email || "").trim().toLowerCase();
      const cleanPassword = String(password || "");

      if (!cleanName || !cleanEmail || cleanPassword.length < 6) {
        return send(res, 400, {
          error: "Name, email and password of at least 6 characters are required."
        });
      }

      const { data: existing, error: checkError } =
        await supabase
          .from("users")
          .select("id")
          .eq("email", cleanEmail)
          .maybeSingle();

      if (checkError) {
        console.error("CHECK USER ERROR:", checkError);

        return send(res, 500, {
          error: "Database error.",
          details: checkError.message
        });
      }

      if (existing) {
        return send(res, 409, {
          error: "Email already exists."
        });
      }

      const role = roleForEmail(cleanEmail);
      const hp = hashPassword(cleanPassword);

      const user = {
        id: crypto.randomUUID(),
        name: cleanName,
        email: cleanEmail,
        password_hash: hp.hash,
        salt: hp.salt,
        role,
        status:
          role === "owner" || role === "admin"
            ? "approved"
            : "pending"
      };

      const { data, error } =
        await supabase
          .from("users")
          .insert(user)
          .select("*")
          .single();

      if (error) {
        console.error("SIGNUP ERROR:", error);

        return send(res, 500, {
          error: "Could not create account.",
          details: error.message
        });
      }

      return send(res, 201, {
        message:
          role === "owner" || role === "admin"
            ? "Account created successfully. You can now log in."
            : "Account created. It is pending approval.",
        status: data.status,
        role: data.role
      });

    } catch (err) {
      console.error("SIGNUP SERVER ERROR:", err);

      return send(res, 500, {
        error: "Could not create account.",
        details: err.message
      });
    }
  }

  // LOGIN
  if (req.method === "POST" && req.url === "/api/login") {
    try {
      const { email, password } = req.body || {};

      const cleanEmail = String(email || "")
        .trim()
        .toLowerCase();

      const cleanPassword = String(password || "");

      const { data: user, error } =
        await supabase
          .from("users")
          .select("*")
          .eq("email", cleanEmail)
          .maybeSingle();

      if (error) {
        console.error("LOGIN DATABASE ERROR:", error);

        return send(res, 500, {
          error: "Database error.",
          details: error.message
        });
      }

      if (!user) {
        return send(res, 401, {
          error: "Incorrect email or password."
        });
      }

      if (
        !verifyPassword(
          cleanPassword,
          user.salt,
          user.password_hash
        )
      ) {
        return send(res, 401, {
          error: "Incorrect email or password."
        });
      }

      const role = roleForEmail(user.email);

      // Owner/Admin automatically approved
      if (role === "owner" || role === "admin") {
        if (
          user.role !== role ||
          user.status !== "approved"
        ) {
          await supabase
            .from("users")
            .update({
              role,
              status: "approved"
            })
            .eq("id", user.id);

          user.role = role;
          user.status = "approved";
        }
      }

      if (user.status !== "approved") {
        return send(res, 403, {
          error: "Your account is pending approval.",
          status: user.status,
          instagram: "https://www.instagram.com/ermik905/"
        });
      }

      // Simple signed token
      const payload = Buffer
        .from(JSON.stringify({
          id: user.id,
          exp: Date.now() + 7 * 24 * 60 * 60 * 1000
        }))
        .toString("base64url");

      const secret =
        process.env.SUPABASE_SECRET_KEY;

      const signature =
        crypto
          .createHmac("sha256", secret)
          .update(payload)
          .digest("base64url");

      const token = `${payload}.${signature}`;

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
      console.error("LOGIN SERVER ERROR:", err);

      return send(res, 500, {
        error: "Server error.",
        details: err.message
      });
    }
  }

  return send(res, 404, {
    error: "Not found"
  });
};
