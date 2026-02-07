const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const UserAgents = require("user-agents");
const path = require("path");

const BASE_URL = "https://api.gobiz.co.id";
const PORT = process.env.PORT || 3000;

const COOKIE_NAME = process.env.COOKIE_NAME || "gobiz_sess";
const SECRET = process.env.SESSION_SECRET || "";

// ====== Safety checks ======
if (!SECRET || SECRET.length < 32) {
  console.warn("SESSION_SECRET harus >= 32 karakter (set di ENV Vercel).");
}

const app = express();
app.set("trust proxy", 1); // penting buat Vercel/behind proxy (secure cookie & proto)
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true })); // x-www-form-urlencoded
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

// ===== HTTP client =====
const http = axios.create({
  timeout: 30000,
  validateStatus: () => true,
});

// ===== Crypto Cookie (AES-256-GCM) =====
function key32() {
  // tetap produce 32 bytes walau SECRET kosong (tapi warning sudah)
  return crypto.createHash("sha256").update(String(SECRET)).digest();
}

function encryptJSON(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32(), iv);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64url");
}

function decryptJSON(token) {
  const buf = Buffer.from(token, "base64url");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32(), iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(dec.toString("utf8"));
}

// ===== Helpers =====
function wantsJson(req) {
  const a = String(req.headers.accept || "");
  return a.includes("application/json");
}

function safeMsg(err, fallback = "FAILED") {
  const m = (err && err.message) ? String(err.message) : String(fallback);
  return m.slice(0, 220);
}

function isHttps(req) {
  // Vercel set x-forwarded-proto: https
  const xf = String(req.headers["x-forwarded-proto"] || "");
  if (xf) return xf.includes("https");
  // fallback
  return req.secure === true;
}

function normalizePhone(raw) {
  // allow digits only, remove leading 0 (umum di ID)
  const d = String(raw || "").replace(/\D/g, "");
  if (!d) return "";
  return d.startsWith("0") ? d.slice(1) : d;
}

function normalizeOtp(raw) {
  return String(raw || "").replace(/\D/g, "");
}

// ===== Session =====
function newSession() {
  return {
    accessToken: null,
    refreshToken: null,
    tokenExpiry: null,

    uniqueId: crypto.randomUUID(),
    ua: new UserAgents({ deviceCategory: "desktop" }).toString(),
    lastRequest: 0,

    otpToken: null,
    otpExpiresAt: null,
    otpLength: 6,
  };
}

function getSession(req) {
  const raw = req.cookies[COOKIE_NAME];
  if (!raw) return null;
  try {
    return decryptJSON(raw);
  } catch {
    return null;
  }
}

function setSession(req, res, session) {
  // simpan minimal supaya cookie kecil
  const payload = {
    accessToken: session.accessToken || null,
    refreshToken: session.refreshToken || null,
    tokenExpiry: session.tokenExpiry || null,
    uniqueId: session.uniqueId,
    ua: session.ua,
    lastRequest: session.lastRequest || 0,

    otpToken: session.otpToken || null,
    otpExpiresAt: session.otpExpiresAt || null,
    otpLength: Number(session.otpLength || 6) || 6,
  };

  const token = encryptJSON(payload);

  // cookie limit ~4KB
  if (Buffer.byteLength(token, "utf8") > 3500) {
    throw new Error("COOKIE_TOO_LARGE: gunakan storage server (Redis/KV) jika token membesar.");
  }

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" ? isHttps(req) : false,
    sameSite: "lax",
    path: "/",
    maxAge: 8 * 60 * 60 * 1000, // 8h
  });
}

function clearSession(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function isLoggedIn(sess) {
  return !!sess?.accessToken;
}

// ===== GoBiz Headers =====
function headers(session, auth = false) {
  return {
    "Content-Type": "application/json",
    Accept: "application/json, text/plain, */*",
    "Accept-Language": "id",
    Origin: "https://portal.gofoodmerchant.co.id",
    Referer: "https://portal.gofoodmerchant.co.id/",
    "Authentication-Type": "go-id",
    "Gojek-Country-Code": "ID",
    "Gojek-Timezone": "Asia/Jakarta",
    "X-Appid": "go-biz-web-dashboard",
    "X-Appversion": "platform-v3.97.0-b986b897",
    "X-Deviceos": "Web",
    "X-Phonemake": "Windows 10 64-bit",
    "X-Phonemodel": "Chrome 143.0.0.0 on Windows 10 64-bit",
    "X-Platform": "Web",
    "X-Uniqueid": session.uniqueId,
    "X-User-Type": "merchant",
    "User-Agent": session.ua,
    ...(auth ? { Authorization: `Bearer ${session.accessToken}` } : {}),
  };
}

async function rateLimit(session) {
  const diff = Date.now() - (session.lastRequest || 0);
  if (diff < 2000) await new Promise((r) => setTimeout(r, 2000 - diff));
  session.lastRequest = Date.now();
}

// ===== GoBiz Actions =====
async function loginEmail(session, email, password) {
  await rateLimit(session);

  await http.post(
    `${BASE_URL}/goid/login/request`,
    { email, login_type: "password", client_id: "go-biz-web-new" },
    { headers: headers(session) }
  );

  await new Promise((r) => setTimeout(r, 2500));
  await rateLimit(session);

  const res = await http.post(
    `${BASE_URL}/goid/token`,
    {
      client_id: "go-biz-web-new",
      grant_type: "password",
      data: { email, password, user_type: "merchant" },
    },
    { headers: headers(session) }
  );

  if (res.status !== 200) throw new Error("LOGIN_FAILED");

  session.accessToken = res.data.access_token;
  session.refreshToken = res.data.refresh_token;
  session.tokenExpiry = Date.now() + res.data.expires_in * 1000;

  // clear otp temp
  session.otpToken = null;
  session.otpExpiresAt = null;
  session.otpLength = 6;
}

async function requestOTP(session, phone, countryCode = "62") {
  await rateLimit(session);

  const res = await http.post(
    `${BASE_URL}/goid/login/request`,
    { client_id: "go-biz-web-new", phone_number: phone, country_code: countryCode },
    { headers: { ...headers(session), Authorization: "Bearer" } }
  );

  if (res.status !== 200) throw new Error("OTP_REQUEST_FAILED");

  const otpToken = res.data?.data?.otp_token;
  const exp = Number(res.data?.data?.otp_expires_in || 0);
  const len = Number(res.data?.data?.otp_length || 6) || 6;

  if (!otpToken) throw new Error("OTP_TOKEN_MISSING");

  session.otpToken = otpToken;
  session.otpExpiresAt = Date.now() + exp * 1000;
  session.otpLength = len;

  return { expiresIn: exp, otpLength: len };
}

async function verifyOTP(session, otp) {
  await rateLimit(session);

  const otpToken = session.otpToken;
  if (!otpToken) throw new Error("OTP_TOKEN_NOT_FOUND: request OTP dulu.");

  const res = await http.post(
    `${BASE_URL}/goid/token`,
    {
      client_id: "go-biz-web-new",
      grant_type: "otp",
      data: { otp, otp_token: otpToken },
    },
    { headers: { ...headers(session), Authorization: "Bearer" } }
  );

  if (res.status !== 200) throw new Error("OTP_VERIFY_FAILED");

  session.accessToken = res.data.access_token;
  session.refreshToken = res.data.refresh_token;
  session.tokenExpiry = Date.now() + res.data.expires_in * 1000;

  // clear otp temp
  session.otpToken = null;
  session.otpExpiresAt = null;
  session.otpLength = 6;
}

async function refreshToken(session) {
  if (!session.refreshToken) return false;
  await rateLimit(session);

  const res = await http.post(
    `${BASE_URL}/goid/token`,
    {
      client_id: "go-biz-web-new",
      grant_type: "refresh_token",
      data: { refresh_token: session.refreshToken, user_type: "merchant" },
    },
    { headers: headers(session) }
  );

  if (res.status !== 200) {
    session.accessToken = null;
    session.refreshToken = null;
    session.tokenExpiry = null;
    return false;
  }

  session.accessToken = res.data.access_token;
  session.refreshToken = res.data.refresh_token || session.refreshToken;
  session.tokenExpiry = Date.now() + res.data.expires_in * 1000;
  return true;
}

async function authRequest(session, method, url, data) {
  if (!session.accessToken) throw new Error("NOT_LOGGED_IN");
  await rateLimit(session);

  let res = await http.request({ method, url, data, headers: headers(session, true) });

  if (res.status === 401) {
    const ok = await refreshToken(session);
    if (!ok) throw new Error("SESSION_EXPIRED");
    await rateLimit(session);
    res = await http.request({ method, url, data, headers: headers(session, true) });
  }

  if (res.status < 200 || res.status >= 300) {
    const msg = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
    throw new Error(`REQUEST_FAILED_${res.status}: ${msg}`.slice(0, 400));
  }

  return res.data;
}

async function getMerchantId(session) {
  const r = await authRequest(session, "POST", `${BASE_URL}/v1/merchants/search`, {
    from: 0,
    to: 1,
    _source: ["id"],
  });
  return r?.hits?.[0]?.id || "";
}

async function searchJournals(session, merchantId, fromISO, toISO) {
  return authRequest(session, "POST", `${BASE_URL}/journals/search`, {
    from: 0,
    size: 50,
    sort: { time: { order: "desc" } },
    included_categories: { incoming: ["transaction_share", "action"] },
    query: [
      {
        op: "and",
        clauses: [
          { field: "metadata.transaction.merchant_id", op: "equal", value: merchantId },
          { field: "metadata.transaction.transaction_time", op: "gte", value: fromISO },
          { field: "metadata.transaction.transaction_time", op: "lte", value: toISO },
        ],
      },
    ],
  });
}

function toSimple(tx) {
  const t = tx?.metadata?.transaction || {};
  const amount = Number(t?.amount?.value ?? t?.amount ?? t?.gross_amount ?? tx?.amount ?? 0) || 0;

  return {
    id: tx?.id || t?.order_id || t?.id || "-",
    time: t?.transaction_time || tx?.time || "-",
    type: "INCOMING",
    amount,
    currency: t?.amount?.currency || "IDR",
    method: t?.payment_method || t?.payment_type || "UNKNOWN",
    status: t?.status || tx?.status || "UNKNOWN",
    note: t?.remark || t?.description || "Pembayaran masuk",
  };
}

function todayRangeJakarta() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const dd = String(now.getDate()).padStart(2, "0");
  const day = `${yyyy}-${mm}-${dd}`;
  return {
    fromISO: `${day}T00:00:00+07:00`,
    toISO: `${day}T23:59:59+07:00`,
    date: day,
  };
}

// ===== UI helpers =====
function renderNote() {
  return "Credential (email/password/OTP) tidak disimpan. Sistem hanya menyimpan token sesi terenkripsi sementara di cookie httpOnly untuk mengambil data merchant/mutasi.";
}

function toastPayload(req) {
  const t = String(req.query?.t || "");
  const m = String(req.query?.m || "");
  if (!t || !m) return null;
  const type = ["success", "error", "info", "warning"].includes(t) ? t : "info";
  return { type, message: m.slice(0, 220) };
}

// ===== Health =====
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// ===== Pages =====
app.get("/", (req, res) => {
  const sess = getSession(req);
  res.render("index", {
    loggedIn: isLoggedIn(sess),
    note: renderNote(),
    toast: toastPayload(req),
  });
});

app.get("/dashboard", (req, res) => {
  const sess = getSession(req);
  if (!isLoggedIn(sess)) {
    return res.redirect("/?t=warning&m=" + encodeURIComponent("Silakan connect terlebih dahulu."));
  }
  res.render("dashboard", {
    note: renderNote(),
    toast: toastPayload(req),
    merchantId: String(req.query.merchantId || ""),
    json: null,
  });
});

// ===== Auth actions =====
app.post("/connect/email", async (req, res) => {
  const { email, password } = req.body || {};
  let sess = getSession(req) || newSession();

  try {
    const e = String(email || "").trim();
    const p = String(password || "");
    if (!e || !p) throw new Error("EMAIL_PASSWORD_REQUIRED");

    await loginEmail(sess, e, p);
    setSession(req, res, sess);

    return res.redirect("/dashboard?t=success&m=" + encodeURIComponent("Connect sukses. Credential tidak disimpan."));
  } catch (err) {
    return res.redirect("/?t=error&m=" + encodeURIComponent(safeMsg(err, "LOGIN_FAILED")));
  }
});

// OTP request: supports JSON (AJAX) + redirect fallback
app.post("/connect/otp/request", async (req, res) => {
  const { phone, countryCode } = req.body || {};
  let sess = getSession(req) || newSession();

  try {
    const cc = String(countryCode || "62").replace(/\D/g, "") || "62";
    const ph = normalizePhone(phone);

    if (!ph) throw new Error("PHONE_REQUIRED");

    const r = await requestOTP(sess, ph, cc);
    setSession(req, res, sess);

    if (wantsJson(req)) {
      return res.json({ ok: true, expiresIn: r.expiresIn, otpLength: r.otpLength });
    }

    return res.redirect(
      "/?otp=1&t=success&m=" + encodeURIComponent(`OTP terkirim. Exp ${r.expiresIn}s.`) + "#otp"
    );
  } catch (err) {
    if (wantsJson(req)) {
      return res.status(400).json({ ok: false, message: safeMsg(err, "OTP_REQUEST_FAILED") });
    }
    return res.redirect(
      "/?t=error&m=" + encodeURIComponent(safeMsg(err, "OTP_REQUEST_FAILED")) + "#otp"
    );
  }
});

app.post("/connect/otp/verify", async (req, res) => {
  const { otp } = req.body || {};
  let sess = getSession(req) || newSession();

  try {
    if (!sess.otpToken) throw new Error("OTP_TOKEN_NOT_FOUND: request OTP dulu.");

    if (sess.otpExpiresAt && Date.now() > sess.otpExpiresAt) {
      sess.otpToken = null;
      sess.otpExpiresAt = null;
      sess.otpLength = 6;
      setSession(req, res, sess);
      throw new Error("OTP_EXPIRED: request OTP ulang.");
    }

    const code = normalizeOtp(otp);
    const needLen = Number(sess.otpLength || 6) || 6;
    if (code.length !== needLen) throw new Error("OTP_INVALID_LENGTH");

    await verifyOTP(sess, code);
    setSession(req, res, sess);

    return res.redirect(
      "/dashboard?t=success&m=" + encodeURIComponent("OTP verify sukses. Credential tidak disimpan.")
    );
  } catch (err) {
    return res.redirect("/?t=error&m=" + encodeURIComponent(safeMsg(err, "OTP_VERIFY_FAILED")) + "#otp");
  }
});

// ===== Merchant & Mutasi =====
app.post("/merchant", async (req, res) => {
  const sess = getSession(req);
  if (!isLoggedIn(sess)) {
    return res.redirect("/?t=warning&m=" + encodeURIComponent("Silakan connect terlebih dahulu."));
  }

  try {
    const merchantId = await getMerchantId(sess);
    setSession(req, res, sess);

    return res.redirect(
      "/dashboard?t=success&m=" +
        encodeURIComponent("Merchant ID berhasil diambil.") +
        "&merchantId=" + encodeURIComponent(merchantId || "")
    );
  } catch (err) {
    return res.redirect("/dashboard?t=error&m=" + encodeURIComponent(safeMsg(err, "FAILED")));
  }
});

app.post("/mutasi", async (req, res) => {
  const sess = getSession(req);
  if (!isLoggedIn(sess)) {
    return res.redirect("/?t=warning&m=" + encodeURIComponent("Silakan connect terlebih dahulu."));
  }

  const merchantId = String(req.body.merchantId || "").trim();
  if (!merchantId) {
    return res.redirect("/dashboard?t=warning&m=" + encodeURIComponent("Merchant ID kosong."));
  }

  try {
    const { fromISO, toISO, date } = todayRangeJakarta();
    const raw = await searchJournals(sess, merchantId, fromISO, toISO);
    setSession(req, res, sess);

    const hits = Array.isArray(raw?.hits) ? raw.hits : [];
    const simple = hits.map(toSimple);

    const result = {
      ok: true,
      merchant_id: merchantId,
      date,
      range: { fromISO, toISO },
      count: simple.length,
      transactions: simple,
      note: renderNote(),
    };

    return res.render("dashboard", {
      note: renderNote(),
      toast: { type: "success", message: "Mutasi berhasil diambil (manual, simple)." },
      merchantId,
      json: result,
    });
  } catch (err) {
    return res.redirect("/dashboard?t=error&m=" + encodeURIComponent(safeMsg(err, "FAILED")));
  }
});

app.post("/logout", (req, res) => {
  clearSession(res);
  res.redirect("/?t=success&m=" + encodeURIComponent("Logout berhasil."));
});

// ===== OTP status for countdown =====
app.get("/otp/status", (req, res) => {
  const sess = getSession(req);

  const active = !!sess?.otpToken;
  const otpLength = Number(sess?.otpLength || 6) || 6;
  const expiresAt = Number(sess?.otpExpiresAt || 0) || 0;

  if (active && expiresAt && Date.now() > expiresAt) {
    // bersihin otp temp
    sess.otpToken = null;
    sess.otpExpiresAt = null;
    sess.otpLength = 6;
    try { setSession(req, res, sess); } catch {}
    return res.json({ active: false, otpLength: 6, expiresAt: 0 });
  }

  return res.json({ active, otpLength, expiresAt });
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`Server running http://localhost:${PORT}`);
});
