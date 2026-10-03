require("dotenv").config();

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { pool, query } = require("./database");

const PORT = Number(process.env.PORT) || 3100;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

/* ---------------- JWT ---------------- */

const b64 = (value) =>
  Buffer.from(
    typeof value === "string" ? value : JSON.stringify(value)
  ).toString("base64url");

const signature = (value) =>
  crypto
    .createHmac("sha256", JWT_SECRET)
    .update(value)
    .digest("base64url");

function signToken(userId) {
  const header = b64({ alg: "HS256", typ: "JWT" });

  const payload = b64({
    sub: String(userId),
    exp: Math.floor(Date.now() / 1000) + 86400
  });

  const data = `${header}.${payload}`;

  return `${data}.${signature(data)}`;
}

function verifyToken(token) {
  try {
    const [header, payload, suppliedSignature] =
      String(token || "").split(".");

    if (!header || !payload || !suppliedSignature) return null;

    const expected = signature(`${header}.${payload}`);

    if (
      suppliedSignature.length !== expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(suppliedSignature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!data.exp || data.exp * 1000 <= Date.now()) return null;

    return data.sub;
  } catch {
    return null;
  }
}

/* ---------------- HELPERS ---------------- */

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg"
};

function send(res, status, data) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });

  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;

      if (body.length > 500000) {
        reject(new Error("Request too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!body) return resolve({});

      try {
        resolve(JSON.parse(body));
      } catch {
        resolve({});
      }
    });
  });
}

function publicUser(user) {
  return {
    id: String(user.id),
    name: user.name,
    email: user.email,
    role: user.role,
    active: user.active
  };
}

async function audit(userId, action, entityType, entityId, details = {}) {
  try {
    await query(
      `
      INSERT INTO audit_logs
      (user_id, action, entity_type, entity_id, details)
      VALUES ($1,$2,$3,$4,$5)
      `,
      [
        userId || null,
        action,
        entityType || null,
        entityId || null,
        JSON.stringify(details)
      ]
    );
  } catch (error) {
    console.error("Audit error:", error.message);
  }
}

/* ---------------- DATABASE STARTUP ---------------- */

async function initializeDatabase() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(30) NOT NULL
        CHECK (role IN ('admin','patient','doctor','pharmacy','reception')),
      phone VARCHAR(30),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS patients (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
      patient_code VARCHAR(30) UNIQUE,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255),
      phone VARCHAR(30),
      gender VARCHAR(30),
      date_of_birth DATE,
      blood_group VARCHAR(10),
      address TEXT,
      emergency_contact VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS doctors (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
      doctor_code VARCHAR(30) UNIQUE,
      name VARCHAR(120) NOT NULL,
      specialization VARCHAR(120),
      phone VARCHAR(30),
      email VARCHAR(255),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS appointments (
      id BIGSERIAL PRIMARY KEY,
      patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      doctor_id BIGINT REFERENCES doctors(id) ON DELETE SET NULL,
      appointment_date DATE NOT NULL,
      appointment_time TIME,
      reason TEXT,
      status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','confirmed','completed','cancelled')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS medical_records (
      id BIGSERIAL PRIMARY KEY,
      patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      doctor_id BIGINT REFERENCES doctors(id) ON DELETE SET NULL,
      appointment_id BIGINT REFERENCES appointments(id) ON DELETE SET NULL,
      diagnosis TEXT,
      symptoms TEXT,
      treatment TEXT,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS medicines (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(160) NOT NULL,
      generic_name VARCHAR(160),
      batch_number VARCHAR(100),
      quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
      unit_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      expiry_date DATE,
      supplier VARCHAR(160),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS prescriptions (
      id BIGSERIAL PRIMARY KEY,
      patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      doctor_id BIGINT REFERENCES doctors(id) ON DELETE SET NULL,
      appointment_id BIGINT REFERENCES appointments(id) ON DELETE SET NULL,
      notes TEXT,
      status VARCHAR(30) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','dispensed','cancelled')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS prescription_items (
      id BIGSERIAL PRIMARY KEY,
      prescription_id BIGINT NOT NULL
        REFERENCES prescriptions(id) ON DELETE CASCADE,
      medicine_id BIGINT REFERENCES medicines(id) ON DELETE SET NULL,
      medicine_name VARCHAR(160) NOT NULL,
      dosage VARCHAR(100),
      frequency VARCHAR(100),
      duration VARCHAR(100),
      instructions TEXT
    );

    CREATE TABLE IF NOT EXISTS dispensations (
      id BIGSERIAL PRIMARY KEY,
      prescription_id BIGINT REFERENCES prescriptions(id) ON DELETE SET NULL,
      patient_id BIGINT REFERENCES patients(id) ON DELETE SET NULL,
      pharmacist_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      total_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      dispensed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS bills (
      id BIGSERIAL PRIMARY KEY,
      patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      appointment_id BIGINT REFERENCES appointments(id) ON DELETE SET NULL,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      payment_method VARCHAR(30),
      payment_status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (payment_status IN ('pending','paid','cancelled')),
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(160) NOT NULL,
      entity_type VARCHAR(80),
      entity_id BIGINT,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const adminEmail = String(
    process.env.ADMIN_EMAIL || "admin@hospital.local"
  )
    .trim()
    .toLowerCase();

  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPassword) {
    console.warn(
      "ADMIN_PASSWORD is not configured. Existing admin accounts can still login."
    );
    return;
  }

  const existing = await query(
    `SELECT id FROM users WHERE email=$1 LIMIT 1`,
    [adminEmail]
  );

  if (!existing.rows.length) {
    const hash = await bcrypt.hash(adminPassword, 12);

    await query(
      `
      INSERT INTO users
      (name,email,password_hash,role,active)
      VALUES ($1,$2,$3,'admin',TRUE)
      `,
      ["Hospital Administrator", adminEmail, hash]
    );

    console.log("Initial administrator created.");
  }
}

/* ---------------- AUTH ---------------- */

async function authenticatedUser(req) {
  const token = String(req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  const userId = verifyToken(token);

  if (!userId) return null;

  const result = await query(
    `
    SELECT id,name,email,role,active
    FROM users
    WHERE id=$1 AND active=TRUE
    LIMIT 1
    `,
    [userId]
  );

  return result.rows[0] || null;
}

function allowed(user, roles) {
  return user && roles.includes(user.role);
}

/* ---------------- SERVER ---------------- */

const server = http.createServer(async (req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;

  if (!pathname.startsWith("/api/")) {
    const publicRoot = path.join(__dirname, "public");

    let requested = pathname === "/" ? "index.html" : pathname.slice(1);

    const file = path.normalize(path.join(publicRoot, requested));

    if (
      !file.startsWith(publicRoot) ||
      !fs.existsSync(file) ||
      fs.statSync(file).isDirectory()
    ) {
      res.writeHead(404);
      return res.end("Not found");
    }

    res.writeHead(200, {
      "content-type":
        MIME[path.extname(file).toLowerCase()] ||
        "application/octet-stream",
      "cache-control": "no-cache"
    });

    return fs.createReadStream(file).pipe(res);
  }

  try {
    const method = req.method;
    const body = await readBody(req);

    /* HEALTH */

    if (pathname === "/api/ping") {
      return send(res, 200, { ok: true });
    }

    if (pathname === "/api/health") {
      const db = await query(
        `SELECT current_database() AS database, NOW() AS time`
      );

      return send(res, 200, {
        ok: true,
        database: "Neon PostgreSQL",
        databaseName: db.rows[0].database,
        time: db.rows[0].time
      });
    }

    /* LOGIN */

    if (pathname === "/api/login" && method === "POST") {
      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const password = String(body.password || "");

      if (!email || !password) {
        return send(res, 400, {
          error: "Email and password are required."
        });
      }

      const result = await query(
        `
        SELECT *
        FROM users
        WHERE LOWER(email)=LOWER($1)
          AND active=TRUE
        LIMIT 1
        `,
        [email]
      );

      const user = result.rows[0];

      if (
        !user ||
        !(await bcrypt.compare(password, user.password_hash))
      ) {
        return send(res, 401, {
          error: "Wrong email or password."
        });
      }

      await audit(user.id, "login", "users", user.id);

      return send(res, 200, {
        token: signToken(user.id),
        user: publicUser(user)
      });
    }

    const user = await authenticatedUser(req);

    if (!user) {
      return send(res, 401, {
        error: "Please sign in again."
      });
    }

    /* CURRENT USER */

    if (pathname === "/api/me") {
      return send(res, 200, {
        user: publicUser(user)
      });
    }

    /* USERS */

    if (pathname === "/api/users" && method === "GET") {
      if (!allowed(user, ["admin"])) {
        return send(res, 403, { error: "Access denied." });
      }

      const result = await query(`
        SELECT id,name,email,role,phone,active,created_at
        FROM users
        ORDER BY created_at DESC
      `);

      return send(res, 200, result.rows);
    }

    if (pathname === "/api/users" && method === "POST") {
      if (!allowed(user, ["admin"])) {
        return send(res, 403, { error: "Access denied." });
      }

      const name = String(body.name || "").trim();
      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const password = String(body.password || "");
      let role = String(body.role || "").toLowerCase();

      if (role === "pharmacist") role = "pharmacy";

      const roles = [
        "admin",
        "patient",
        "doctor",
        "pharmacy",
        "reception"
      ];

      if (!name || !email || password.length < 8 || !roles.includes(role)) {
        return send(res, 400, {
          error:
            "Name, valid role and password of at least 8 characters are required."
        });
      }

      const duplicate = await query(
        `SELECT id FROM users WHERE LOWER(email)=LOWER($1)`,
        [email]
      );

      if (duplicate.rows.length) {
        return send(res, 409, {
          error: "Email already exists."
        });
      }

      const hash = await bcrypt.hash(password, 12);

      const result = await query(
        `
        INSERT INTO users
        (name,email,password_hash,role,phone,active)
        VALUES ($1,$2,$3,$4,$5,TRUE)
        RETURNING id,name,email,role,phone,active,created_at
        `,
        [name, email, hash, role, body.phone || null]
      );

      const created = result.rows[0];

      if (role === "patient") {
        await query(
          `
          INSERT INTO patients
          (user_id,patient_code,name,email,phone)
          VALUES ($1,$2,$3,$4,$5)
          `,
          [
            created.id,
            `PAT-${String(created.id).padStart(5, "0")}`,
            name,
            email,
            body.phone || null
          ]
        );
      }

      if (role === "doctor") {
        await query(
          `
          INSERT INTO doctors
          (user_id,doctor_code,name,email,phone,specialization)
          VALUES ($1,$2,$3,$4,$5,$6)
          `,
          [
            created.id,
            `DOC-${String(created.id).padStart(5, "0")}`,
            name,
            email,
            body.phone || null,
            body.specialization || null
          ]
        );
      }

      await audit(user.id, "create", "users", created.id, {
        role
      });

      return send(res, 201, created);
    }

    /* DOCTORS */

    if (pathname === "/api/doctors" && method === "GET") {
      const result = await query(`
        SELECT
          d.id,
          d.user_id AS "userId",
          d.name,
          d.specialization,
          d.email,
          d.phone
        FROM doctors d
        JOIN users u ON u.id=d.user_id
        WHERE u.active=TRUE
        ORDER BY d.name
      `);

      return send(res, 200, result.rows);
    }

    /* PATIENTS */

    if (pathname === "/api/patients" && method === "GET") {
      if (
        !allowed(user, [
          "admin",
          "reception",
          "doctor",
          "pharmacy",
          "patient"
        ])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      let result;

      if (user.role === "patient") {
        result = await query(
          `
          SELECT *
          FROM patients
          WHERE user_id=$1
          `,
          [user.id]
        );
      } else {
        result = await query(`
          SELECT *
          FROM patients
          ORDER BY created_at DESC
        `);
      }

      return send(res, 200, result.rows);
    }

    if (pathname === "/api/patients" && method === "POST") {
      if (!allowed(user, ["admin", "reception"])) {
        return send(res, 403, { error: "Access denied." });
      }

      const name = String(body.name || "").trim();
      const phone = String(body.phone || "").trim();

      if (!name) {
        return send(res, 400, {
          error: "Patient name is required."
        });
      }

      const result = await query(
        `
        INSERT INTO patients
        (
          patient_code,
          name,
          email,
          phone,
          gender,
          date_of_birth,
          blood_group,
          address,
          emergency_contact
        )
        VALUES
        (
          'PAT-' || LPAD(nextval('patients_id_seq')::TEXT,5,'0'),
          $1,$2,$3,$4,$5,$6,$7,$8
        )
        RETURNING *
        `,
        [
          name,
          body.email || null,
          phone || null,
          body.gender || null,
          body.date_of_birth || null,
          body.blood_group || null,
          body.address || null,
          body.emergency_contact || null
        ]
      );

      await audit(
        user.id,
        "create",
        "patients",
        result.rows[0].id
      );

      return send(res, 201, result.rows[0]);
    }

    /* APPOINTMENTS */

    if (pathname === "/api/appointments" && method === "GET") {
      let sql = `
        SELECT
          a.*,
          p.name AS patient_name,
          d.name AS doctor_name
        FROM appointments a
        JOIN patients p ON p.id=a.patient_id
        LEFT JOIN doctors d ON d.id=a.doctor_id
      `;

      const params = [];

      if (user.role === "patient") {
        sql += `
          WHERE p.user_id=$1
        `;
        params.push(user.id);
      } else if (user.role === "doctor") {
        sql += `
          WHERE d.user_id=$1
        `;
        params.push(user.id);
      } else if (
        !allowed(user, ["admin", "reception", "pharmacy"])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      sql += ` ORDER BY a.appointment_date DESC, a.appointment_time DESC`;

      const result = await query(sql, params);

      return send(res, 200, result.rows);
    }

    if (pathname === "/api/appointments" && method === "POST") {
      if (
        !allowed(user, ["admin", "reception", "patient"])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      let patientId = body.patientId || body.patient_id;

      if (user.role === "patient") {
        const patient = await query(
          `SELECT id FROM patients WHERE user_id=$1 LIMIT 1`,
          [user.id]
        );

        if (!patient.rows.length) {
          return send(res, 400, {
            error: "Patient profile not found."
          });
        }

        patientId = patient.rows[0].id;
      }

      const doctorId = body.doctorId || body.doctor_id;

      if (
        !patientId ||
        !doctorId ||
        !body.date ||
        !body.time
      ) {
        return send(res, 400, {
          error:
            "Patient, doctor, date and time are required."
        });
      }

      const result = await query(
        `
        INSERT INTO appointments
        (
          patient_id,
          doctor_id,
          appointment_date,
          appointment_time,
          reason,
          status
        )
        VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING *
        `,
        [
          patientId,
          doctorId,
          body.date,
          body.time,
          body.reason || null,
          String(body.status || "pending").toLowerCase()
        ]
      );

      await audit(
        user.id,
        "create",
        "appointments",
        result.rows[0].id
      );

      return send(res, 201, result.rows[0]);
    }

    /* MEDICAL RECORDS */

    if (pathname === "/api/records" && method === "GET") {
      let sql = `
        SELECT
          mr.*,
          p.name AS patient_name,
          d.name AS doctor_name
        FROM medical_records mr
        JOIN patients p ON p.id=mr.patient_id
        LEFT JOIN doctors d ON d.id=mr.doctor_id
      `;

      const params = [];

      if (user.role === "patient") {
        sql += ` WHERE p.user_id=$1 `;
        params.push(user.id);
      } else if (
        !allowed(user, ["admin", "doctor"])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      sql += ` ORDER BY mr.created_at DESC`;

      const result = await query(sql, params);

      return send(res, 200, result.rows);
    }

    /* MEDICINES */

    if (pathname === "/api/medicines" && method === "GET") {
      if (
        !allowed(user, [
          "admin",
          "doctor",
          "pharmacy"
        ])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      const result = await query(`
        SELECT *
        FROM medicines
        ORDER BY name
      `);

      return send(res, 200, result.rows);
    }

    if (pathname === "/api/medicines" && method === "POST") {
      if (!allowed(user, ["admin", "pharmacy"])) {
        return send(res, 403, { error: "Access denied." });
      }

      if (!String(body.name || "").trim()) {
        return send(res, 400, {
          error: "Medicine name is required."
        });
      }

      const result = await query(
        `
        INSERT INTO medicines
        (
          name,
          generic_name,
          batch_number,
          quantity,
          unit_price,
          expiry_date,
          supplier
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING *
        `,
        [
          String(body.name).trim(),
          body.generic_name || null,
          body.batch_number || null,
          Number(body.quantity ?? body.stock ?? 0),
          Number(body.unit_price ?? body.price ?? 0),
          body.expiry_date || body.expiry || null,
          body.supplier || null
        ]
      );

      await audit(
        user.id,
        "create",
        "medicines",
        result.rows[0].id
      );

      return send(res, 201, result.rows[0]);
    }

    /* PRESCRIPTIONS */

    if (pathname === "/api/prescriptions" && method === "GET") {
      let sql = `
        SELECT
          pr.*,
          p.name AS patient_name,
          d.name AS doctor_name
        FROM prescriptions pr
        JOIN patients p ON p.id=pr.patient_id
        LEFT JOIN doctors d ON d.id=pr.doctor_id
      `;

      const params = [];

      if (user.role === "patient") {
        sql += ` WHERE p.user_id=$1 `;
        params.push(user.id);
      } else if (
        !allowed(user, [
          "admin",
          "doctor",
          "pharmacy"
        ])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      sql += ` ORDER BY pr.created_at DESC`;

      const result = await query(sql, params);

      return send(res, 200, result.rows);
    }

    /* BILLS */

    if (pathname === "/api/bills" && method === "GET") {
      let sql = `
        SELECT
          b.*,
          p.name AS patient_name
        FROM bills b
        JOIN patients p ON p.id=b.patient_id
      `;

      const params = [];

      if (user.role === "patient") {
        sql += ` WHERE p.user_id=$1 `;
        params.push(user.id);
      } else if (
        !allowed(user, ["admin", "reception"])
      ) {
        return send(res, 403, { error: "Access denied." });
      }

      sql += ` ORDER BY b.created_at DESC`;

      const result = await query(sql, params);

      return send(res, 200, result.rows);
    }

    /* ADMIN DASHBOARD */

    if (pathname === "/api/stats") {
      if (!allowed(user, ["admin"])) {
        return send(res, 403, { error: "Access denied." });
      }

      const result = await query(`
        SELECT
          (SELECT COUNT(*) FROM patients)::INT AS patients,

          (
            SELECT COUNT(*)
            FROM appointments
            WHERE appointment_date=CURRENT_DATE
              AND status <> 'cancelled'
          )::INT AS today,

          (
            SELECT COALESCE(SUM(amount),0)
            FROM bills
            WHERE payment_status='paid'
          )::NUMERIC AS revenue,

          (
            SELECT COUNT(*)
            FROM bills
            WHERE payment_status='pending'
          )::INT AS unpaid,

          (
            SELECT COUNT(*)
            FROM medicines
            WHERE quantity <= 10
          )::INT AS low,

          (
            SELECT COUNT(*)
            FROM medicines
            WHERE expiry_date IS NOT NULL
              AND expiry_date <= CURRENT_DATE + INTERVAL '90 days'
          )::INT AS expiring
      `);

      return send(res, 200, result.rows[0]);
    }

    /* AUDIT */

    if (pathname === "/api/audit") {
      if (!allowed(user, ["admin"])) {
        return send(res, 403, { error: "Access denied." });
      }

      const result = await query(`
        SELECT
          a.*,
          u.name AS user_name
        FROM audit_logs a
        LEFT JOIN users u ON u.id=a.user_id
        ORDER BY a.created_at DESC
        LIMIT 100
      `);

      return send(res, 200, result.rows);
    }

    return send(res, 404, {
      error: "API route not found."
    });
  } catch (error) {
    console.error("[SERVER ERROR]", error);

    return send(res, 500, {
      error: "Server error."
    });
  }
});

/* ---------------- STARTUP ---------------- */

async function start() {
  try {
    await initializeDatabase();

    const check = await query(
      `SELECT current_database() AS database`
    );

    console.log(
      `Connected to Neon PostgreSQL: ${check.rows[0].database}`
    );

    server.listen(PORT, "0.0.0.0", () => {
      console.log(
        `MediCare HMS running: http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error("APPLICATION STARTUP FAILED");
    console.error(error);
    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
});

start();