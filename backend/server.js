"use strict";

require("dotenv").config({ path: require("path").join(__dirname, ".env") });

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");
const path = require("path");

const app = express();

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const PORT = process.env.PORT || 5001;
let databasePromise;

async function getDB() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI not configured");
  }

  if (!databasePromise) {
    const client = new MongoClient(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 7000
    });

    databasePromise = client.connect()
      .then(() => client.db(process.env.MONGODB_DB || "moas_expense"))
      .catch(error => {
        databasePromise = null;
        throw error;
      });
  }

  return databasePromise;
}

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function secureCompare(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function authenticate(req, res, next) {
  try {
    const token = req.cookies.moas_session;
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: "moas-agency"
    });

    if (payload.sub !== "admin") throw new Error("Invalid user");

    next();
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
}

function checkOrigin(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();

  const origin = req.get("origin");
  if (origin && new URL(origin).host !== req.get("host")) {
    return res.status(403).json({ error: "Invalid origin" });
  }

  next();
}

app.use("/api", checkOrigin);

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "MOAS Agency Backend Running"
  });
});

app.get("/api/db-status", asyncRoute(async (req, res) => {
  const db = await getDB();
  await db.command({ ping: 1 });
  res.json({ success: true, database: "connected" });
}));


// MOAS LOGIN RATE LIMIT V1
const { rateLimit } = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: "Too many login attempts" }
});


// MOAS PASSWORD HASH V1
async function verifyAdminPassword(candidate) {
  const stored = process.env.ADMIN_PASSWORD_HASH || "";
  const parts = stored.split("$");

  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }

  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");

  if (salt.length !== 16 || expected.length !== 64) {
    return false;
  }

  const actual = await new Promise((resolve, reject) => {
    crypto.scrypt(
      String(candidate),
      salt,
      64,
      {
        N: 131072,
        r: 8,
        p: 1,
        maxmem: 256 * 1024 * 1024
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
  });

  return crypto.timingSafeEqual(actual, expected);
}

app.post("/api/auth/login", loginLimiter, asyncRoute(async (req, res) => {
  const { email, password } = req.body || {};

  if (!process.env.ADMIN_EMAIL ||
      !process.env.ADMIN_PASSWORD_HASH ||
      !process.env.JWT_SECRET ||
      process.env.JWT_SECRET.length < 32) {
    return res.status(503).json({ error: "Auth not configured" });
  }

  const valid =
    secureCompare(String(email || "").toLowerCase(),
      process.env.ADMIN_EMAIL.toLowerCase()) &&
    await verifyAdminPassword(password || "");

  if (!valid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  await (await getDB()).command({ ping: 1 });

  const token = jwt.sign(
    { sub: "admin" },
    process.env.JWT_SECRET,
    { expiresIn: "1d", issuer: "moas-agency" }
  );

  res.cookie("moas_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/api",
    maxAge: 86400000
  });

  res.json({ success: true });
}));

app.get("/api/auth/me", authenticate, (req, res) => {
  res.json({ authenticated: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("moas_session", { path: "/api" });
  res.json({ success: true });
});

app.get("/api/expenses", authenticate, asyncRoute(async (req, res) => {
  const db = await getDB();
  const expenses = await db.collection("expenses")
    .find({}).sort({ createdAt: -1 }).toArray();
  res.json(expenses);
}));

app.post("/api/expenses", authenticate, asyncRoute(async (req, res) => {
  const { amount, category, description, date } = req.body || {};
  const value = Number(amount);

  if (!Number.isFinite(value) || value <= 0 ||
      typeof category !== "string" ||
      !category.trim() ||
      (date && !/^\d{4}-\d{2}-\d{2}$/.test(date))) {
    return res.status(400).json({ error: "Invalid expense" });
  }

  const expense = {
    amount: value,
    category: category.trim().slice(0, 100),
    description: String(description || "").slice(0, 1000),
    date: date || new Date().toISOString().slice(0, 10),
    createdAt: new Date()
  };

  const db = await getDB();
  const result = await db.collection("expenses").insertOne(expense);

  res.status(201).json({ ...expense, _id: result.insertedId });
}));


// MOAS MONGODB MODULE API V1

const MODULES = new Set([
  "expenses",
  "income",
  "employees",
  "payroll",
  "vendors",
  "vouchers",
  "dollars",
  "plans",
  "transfers",
  "reminders",
  "floats",
  "assets",
  "stock"
]);

function validModule(req, res, next) {
  if (!MODULES.has(req.params.module)) {
    return res.status(400).json({
      error: "Invalid module"
    });
  }
  next();
}

function validId(req, res, next) {
  if (
    typeof req.params.id !== "string" ||
    !/^[a-zA-Z0-9_-]{1,100}$/.test(req.params.id)
  ) {
    return res.status(400).json({
      error: "Invalid record ID"
    });
  }
  next();
}

app.get(
  "/api/state",
  authenticate,
  asyncRoute(async (req, res) => {
    const db = await getDB();
    const result = {};

    await Promise.all(
      [...MODULES].map(async module => {
        const records = await db
          .collection(module)
          .find({})
          .toArray();

        result[module] = records.map(record => {
          const { _id, ...data } = record;
          return {
            ...data,
            id: String(_id)
          };
        });
      })
    );

    const config = await db
      .collection("app_config")
      .findOne({ _id: "main" });

    if (config) {
      const { _id, ...data } = config;
      result.cfg = data;
    } else {
      result.cfg = null;
    }

    res.json(result);
  })
);

app.put(
  "/api/state/config",
  authenticate,
  asyncRoute(async (req, res) => {
    if (
      !req.body ||
      typeof req.body !== "object" ||
      Array.isArray(req.body)
    ) {
      return res.status(400).json({
        error: "Invalid configuration"
      });
    }

    const db = await getDB();

    const { _id, ...data } = req.body;

    await db.collection("app_config").replaceOne(
      { _id: "main" },
      { ...data, _id: "main" },
      { upsert: true }
    );

    res.json({ success: true });
  })
);

app.put(
  "/api/state/:module/:id",
  authenticate,
  validModule,
  validId,
  asyncRoute(async (req, res) => {
    if (
      !req.body ||
      typeof req.body !== "object" ||
      Array.isArray(req.body)
    ) {
      return res.status(400).json({
        error: "Invalid record"
      });
    }

    const db = await getDB();

    const { _id, id, ...data } = req.body;

    await db.collection(req.params.module).replaceOne(
      { _id: req.params.id },
      {
        ...data,
        _id: req.params.id,
        id: req.params.id
      },
      { upsert: true }
    );

    res.json({
      success: true,
      id: req.params.id
    });
  })
);

app.delete(
  "/api/state/:module/:id",
  authenticate,
  validModule,
  validId,
  asyncRoute(async (req, res) => {
    const db = await getDB();

    const result = await db
      .collection(req.params.module)
      .deleteOne({ _id: req.params.id });

    res.json({
      success: true,
      deleted: result.deletedCount
    });
  })
);

app.use("/api", (req, res) => {
  res.status(404).json({ error: "API route not found" });
});


const frontendRoot = path.join(__dirname, "..", "public");

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendRoot, "index.html"));
});

for (const file of ["index.html", "style.css", "script.js"]) {
  app.get("/" + file, (req, res) => {
    res.sendFile(path.join(frontendRoot, file));
  });
}


app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ error: "Internal server error" });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log("MOAS Backend running on port " + PORT);
  });
}

module.exports = app;
