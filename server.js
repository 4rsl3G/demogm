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

if (SECRET.length < 32) {
  console.warn("SESSION_SECRET harus >= 32 karakter");
}

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

const http = axios.create({
  timeout: 30000,
  validateStatus: () => true
});

// ===== Crypto Cookie (AES-256-GCM) =====
function key32() {
  return crypto.createHash("sha256").update(SECRET).digest();
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
    otpLength: 6
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

function setSession(res, session) {
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
    otpLength: Number(session.otpLength || 6) || 6
  };

  const token = encryptJSON(payload);

  // cookie limit ~4KB, jaga aman
  if (Buffer.byteLength(token, "utf8") > 3500) {
    throw new Error("COOKIE_TOO_LARGE: gunakan storage server (Redis/KV) jika token membesar.");
  }

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // true saat https
    sameSite: "lax",
    path: "/",
    maxAge: 8 * 60 * 60 * 1000
  });
}

function clearSession(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function isLoggedIn(sess) {
  return !!sess?.accessToken;
}

// ===== GoBiz =====
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
    ...(auth ? { Authorization: `Bearer ${session.accessToken}` } : {})
  };
}

async function rateLimit(session) {
  const diff = Date.now() - (session.lastRequest || 0);
  if (diff < 2000) await new Promise((r) => setTimeout(r, 2000 - diff));
  session.lastRequest = Date.now();
}

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
      data: { email, password, user_type: "merchant" }
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
      data: { otp, otp_token: otpToken }
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
      data: { refresh_token: session.refreshToken, user_type: "merchant" }
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
    _source: ["id"]
  });
  return r?.hits?.[0]?.id;
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
          { field: "metadata.transaction.transaction_time", op: "lte", value: toISO }
        ]
      }
    ]
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
    note: t?.remark || t?.description || "Pembayaran masuk"
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
    date: day
  };
}

// ===== UI =====
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

// ===== Pages =====
app.get("/", (req, res) => {
  const sess = getSession(req);
  res.render("index", {
    loggedIn: isLoggedIn(sess),
    note: renderNote(),
    toast: toastPayload(req)
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
    json: null
  });
});

// ===== Auth actions =====
app.post("/connect/email", async (req, res) => {
  const { email, password } = req.body || {};
  let sess = getSession(req) || newSession();

  try {
    await loginEmail(sess, String(email || ""), String(password || ""));
    setSession(res, sess);
    return res.redirect("/dashboard?t=success&m=" + encodeURIComponent("Connect sukses. Credential tidak disimpan."));
  } catch (e) {
    return res.redirect("/?t=error&m=" + encodeURIComponent(e.message || "LOGIN_FAILED"));
  }
});

app.post("/connect/otp/request", async (req, res) => {
  const { phone, countryCode } = req.body || {};
  let sess = getSession(req) || newSession();

  try {
    const r = await requestOTP(sess, String(phone || ""), String(countryCode || "62"));
    setSession(res, sess);
    return res.redirect(
  "/?otp=1&t=success&m=" + encodeURIComponent(`OTP terkirim. Exp ${r.expiresIn}s.`) + "#otp"
);
  } catch (e) {
    return res.redirect("/?t=error&m=" + encodeURIComponent(e.message || "OTP_REQUEST_FAILED") + "#otp");
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
      setSession(res, sess);
      throw new Error("OTP_EXPIRED: request OTP ulang.");
    }

    const code = String(otp || "").replace(/\D/g, "");
    if (code.length !== Number(sess.otpLength || 6)) throw new Error("OTP_INVALID_LENGTH");

    await verifyOTP(sess, code);
    setSession(res, sess);

    return res.redirect(
      "/dashboard?t=success&m=" + encodeURIComponent("OTP verify sukses. Credential tidak disimpan.")
    );
  } catch (e) {
    return res.redirect("/?t=error&m=" + encodeURIComponent(e.message || "OTP_VERIFY_FAILED") + "#otp");
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
    setSession(res, sess);
    return res.redirect(
      "/dashboard?t=success&m=" +
        encodeURIComponent("Merchant ID berhasil diambil.") +
        "&merchantId=" + encodeURIComponent(merchantId || "")
    );
  } catch (e) {
    return res.redirect("/dashboard?t=error&m=" + encodeURIComponent(e.message || "FAILED"));
  }
});

app.post("/mutasi", async (req, res) => {
  const sess = getSession(req);
  if (!isLoggedIn(sess)) {
    return res.redirect("/?t=warning&m=" + encodeURIComponent("Silakan connect terlebih dahulu."));
  }

  const merchantId = String(req.body.merchantId || "");
  if (!merchantId) {
    return res.redirect("/dashboard?t=warning&m=" + encodeURIComponent("Merchant ID kosong."));
  }

  try {
    const { fromISO, toISO, date } = todayRangeJakarta();
    const raw = await searchJournals(sess, merchantId, fromISO, toISO);
    setSession(res, sess);

    const hits = Array.isArray(raw?.hits) ? raw.hits : [];
    const simple = hits.map(toSimple);

    const result = {
      ok: true,
      merchant_id: merchantId,
      date,
      range: { fromISO, toISO },
      count: simple.length,
      transactions: simple,
      note: renderNote()
    };

    return res.render("dashboard", {
      note: renderNote(),
      toast: { type: "success", message: "Mutasi berhasil diambil (manual, simple)." },
      merchantId,
      json: result
    });
  } catch (e) {
    return res.redirect("/dashboard?t=error&m=" + encodeURIComponent(e.message || "FAILED"));
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
    try { setSession(res, sess); } catch {}
    return res.json({ active: false, otpLength: 6, expiresAt: 0 });
  }

  return res.json({ active, otpLength, expiresAt });
});

app.listen(PORT, () => {
  console.log(`Server running http://localhost:${PORT}`);
});
