// =====================================================================
// Insight Club — Worker واحد بملف واحد، بدون أي تثبيت أو Terminal
// انسخ هذا الملف كاملاً والصقه في محرر Cloudflare (Workers & Pages)
// =====================================================================

const ENTITY = "insight-club";
const STAFF_ROLES = ["committee_lead", "manager", "super_admin"];
const ADMIN_ROLES = ["manager", "super_admin"];
const SPECIALIST_ROLES = ["psych_specialist", "psychiatrist", "nutritionist", "coach"];

// ---------- أدوات: معرفات، تشفير كلمات المرور، JWT ----------
function newId() { return crypto.randomUUID(); }

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);
  return `${b64(salt)}.${b64(new Uint8Array(key))}`;
}
async function verifyPassword(password, stored) {
  const [saltB64, hashB64] = (stored || "").split(".");
  if (!saltB64 || !hashB64) return false;
  const salt = unb64(saltB64);
  const key = new Uint8Array(await deriveKey(password, salt));
  const expected = unb64(hashB64);
  if (key.byteLength !== expected.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < key.length; i++) diff |= key[i] ^ expected[i];
  return diff === 0;
}
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
}
function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(str) { return Uint8Array.from(atob(str), (c) => c.charCodeAt(0)); }

async function signJwt(payload, secret) {
  const encHeader = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const encPayload = b64url(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  return `${data}.${await hmac(data, secret)}`;
}
async function verifyJwt(token, secret) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  if ((await hmac(`${h}.${p}`, secret)) !== sig) return null;
  const payload = JSON.parse(atobUrl(p));
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}
async function hmac(data, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(String.fromCharCode(...new Uint8Array(sig)));
}
function b64url(str) { return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function atobUrl(str) { return atob(str.replace(/-/g, "+").replace(/_/g, "/")); }

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" } });
}
function err(message, status = 400) { return json({ error: message }, status); }

async function getUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "");
  if (!token) return null;
  const payload = await verifyJwt(token, env.JWT_SECRET);
  if (!payload) return null;
  return payload; // { sub, role, entity_id, exp }
}

// ---------- التوجيه ----------
const routes = [];
function route(method, pattern, handler, opts = {}) {
  // pattern مثال: "/activities/:id"
  const keys = [];
  const regex = new RegExp("^" + pattern.replace(/:[a-zA-Z]+/g, (m) => { keys.push(m.slice(1)); return "([^/]+)"; }) + "$");
  routes.push({ method, regex, keys, handler, ...opts });
}
function params(match, keys) {
  const p = {};
  keys.forEach((k, i) => (p[k] = match[i + 1]));
  return p;
}

// ================= المصادقة =================
route("POST", "/auth/register", async (req, env, p, body) => {
  const { full_name, email, phone, password } = body;
  if (!full_name || !password || (!email && !phone)) return err("الاسم الكامل وكلمة المرور والبريد أو الهاتف مطلوبة");
  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ? OR phone = ?").bind(email ?? null, phone ?? null).first();
  if (existing) return err("هذا البريد أو الهاتف مسجل مسبقًا", 409);
  const id = newId();
  const hash = await hashPassword(password);
  await env.DB.prepare(`INSERT INTO users (id, entity_id, email, phone, password_hash, full_name, role) VALUES (?, '${ENTITY}', ?, ?, ?, ?, 'member')`)
    .bind(id, email ?? null, phone ?? null, hash, full_name).run();
  const token = await signJwt({ sub: id, role: "member", entity_id: ENTITY, exp: Math.floor(Date.now() / 1000) + 2592000 }, env.JWT_SECRET);
  return json({ token, user: { id, full_name, role: "member" } }, 201);
});

route("POST", "/auth/login", async (req, env, p, body) => {
  const { identifier, password } = body;
  if (!identifier || !password) return err("البريد/الهاتف وكلمة المرور مطلوبة");
  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ? OR phone = ?").bind(identifier, identifier).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) return err("بيانات الدخول غير صحيحة", 401);
  if (user.status !== "active") return err("الحساب موقوف حاليًا", 403);
  const token = await signJwt({ sub: user.id, role: user.role, entity_id: user.entity_id, exp: Math.floor(Date.now() / 1000) + 2592000 }, env.JWT_SECRET);
  return json({ token, user: { id: user.id, full_name: user.full_name, role: user.role, points: user.points } });
});

route("GET", "/auth/me", async (req, env, p, body, user) => {
  if (!user) return err("غير مصرح", 401);
  const row = await env.DB.prepare("SELECT id, full_name, email, phone, avatar_url, bio, role, points, status, created_at FROM users WHERE id = ?").bind(user.sub).first();
  if (!row) return err("المستخدم غير موجود", 404);
  return json(row);
}, { auth: true });

// ================= الأنشطة =================
route("GET", "/activities", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM activities WHERE status = 'published' ORDER BY start_at ASC LIMIT 50").all();
  return json(results);
});
route("GET", "/activities/:id", async (req, env, p) => {
  const a = await env.DB.prepare("SELECT * FROM activities WHERE id = ?").bind(p.id).first();
  return a ? json(a) : err("النشاط غير موجود", 404);
});
route("POST", "/activities", async (req, env, p, body, user) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO activities (id, entity_id, committee_id, title, description, mode, location, start_at, end_at, capacity, qr_code, cover_image_url, status, created_by)
    VALUES (?, '${ENTITY}', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)`)
    .bind(id, body.committee_id ?? null, body.title, body.description ?? null, body.mode ?? "in_person", body.location ?? null,
      body.start_at, body.end_at ?? null, body.capacity ?? null, `activity:${id}`, body.cover_image_url ?? null, user.sub).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });
route("PATCH", "/activities/:id", async (req, env, p, body) => {
  const fields = ["title", "description", "mode", "location", "start_at", "end_at", "capacity", "cover_image_url", "status"];
  const sets = fields.filter((f) => f in body);
  if (!sets.length) return err("لا توجد حقول للتحديث");
  await env.DB.prepare(`UPDATE activities SET ${sets.map((f) => f + " = ?").join(", ")} WHERE id = ?`).bind(...sets.map((f) => body[f]), p.id).run();
  return json({ ok: true });
}, { auth: true, roles: STAFF_ROLES });
route("DELETE", "/activities/:id", async (req, env, p) => {
  await env.DB.prepare("DELETE FROM activities WHERE id = ?").bind(p.id).run();
  return json({ ok: true });
}, { auth: true, roles: STAFF_ROLES });
route("POST", "/activities/:id/register", async (req, env, p, body, user) => {
  const activity = await env.DB.prepare("SELECT capacity FROM activities WHERE id = ?").bind(p.id).first();
  if (!activity) return err("النشاط غير موجود", 404);
  let status = "registered";
  if (activity.capacity != null) {
    const c = await env.DB.prepare("SELECT COUNT(*) as count FROM activity_registrations WHERE activity_id = ? AND status = 'registered'").bind(p.id).first();
    if (c.count >= activity.capacity) status = "waitlisted";
  }
  await env.DB.prepare("INSERT INTO activity_registrations (id, activity_id, user_id, status) VALUES (?, ?, ?, ?)").bind(newId(), p.id, user.sub, status).run();
  return json({ status });
}, { auth: true });
route("POST", "/activities/:id/check-in", async (req, env, p, body) => {
  await env.DB.prepare("UPDATE activity_registrations SET status = 'attended', checked_in_at = datetime('now') WHERE activity_id = ? AND user_id = ?").bind(p.id, body.user_id).run();
  return json({ ok: true });
}, { auth: true, roles: STAFF_ROLES });

// ================= الورشات =================
route("GET", "/workshops", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM workshops WHERE status = 'published' ORDER BY start_at DESC LIMIT 50").all();
  return json(results);
});
route("GET", "/workshops/:id", async (req, env, p) => {
  const w = await env.DB.prepare("SELECT * FROM workshops WHERE id = ?").bind(p.id).first();
  return w ? json(w) : err("الورشة غير موجودة", 404);
});
route("POST", "/workshops", async (req, env, p, body) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO workshops (id, entity_id, committee_id, title, description, video_url, cover_image_url, start_at, status) VALUES (?, '${ENTITY}', ?, ?, ?, ?, ?, ?, 'draft')`)
    .bind(id, body.committee_id ?? null, body.title, body.description ?? null, body.video_url ?? null, body.cover_image_url ?? null, body.start_at ?? null).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });
route("POST", "/workshops/:id/register", async (req, env, p, body, user) => {
  await env.DB.prepare("INSERT INTO workshop_registrations (id, workshop_id, user_id) VALUES (?, ?, ?)").bind(newId(), p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });
route("PATCH", "/workshops/:id/attendance", async (req, env, p, body) => {
  await env.DB.prepare("UPDATE workshop_registrations SET attendance_pct = ? WHERE workshop_id = ? AND user_id = ?").bind(body.attendance_pct, p.id, body.user_id).run();
  if (body.attendance_pct >= 75) {
    const existing = await env.DB.prepare("SELECT certificate_id FROM workshop_registrations WHERE workshop_id = ? AND user_id = ?").bind(p.id, body.user_id).first();
    if (!existing?.certificate_id) {
      const certId = newId();
      const serial = `WS-${Date.now()}-${certId.slice(0, 6)}`;
      await env.DB.prepare(`INSERT INTO certificates (id, entity_id, user_id, source_type, source_id, serial_number, qr_code) VALUES (?, '${ENTITY}', ?, 'workshop', ?, ?, ?)`)
        .bind(certId, body.user_id, p.id, serial, `cert:${certId}`).run();
      await env.DB.prepare("UPDATE workshop_registrations SET certificate_id = ? WHERE workshop_id = ? AND user_id = ?").bind(certId, p.id, body.user_id).run();
      return json({ ok: true, certificate_issued: true, certificate_id: certId });
    }
  }
  return json({ ok: true, certificate_issued: false });
}, { auth: true, roles: STAFF_ROLES });

// ================= الدورات =================
route("GET", "/courses", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM courses WHERE status = 'published' ORDER BY created_at DESC LIMIT 50").all();
  return json(results);
});
route("GET", "/courses/:id", async (req, env, p) => {
  const course = await env.DB.prepare("SELECT * FROM courses WHERE id = ?").bind(p.id).first();
  return course ? json(course) : err("الدورة غير موجودة", 404);
});
route("POST", "/courses", async (req, env, p, body) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO courses (id, entity_id, title, description, cover_image_url, is_free, has_exam, status) VALUES (?, '${ENTITY}', ?, ?, ?, ?, ?, 'draft')`)
    .bind(id, body.title, body.description ?? null, body.cover_image_url ?? null, body.is_free ?? 1, body.has_exam ?? 0).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });
route("POST", "/courses/:id/enroll", async (req, env, p, body, user) => {
  await env.DB.prepare("INSERT INTO course_enrollments (id, course_id, user_id) VALUES (?, ?, ?)").bind(newId(), p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });
route("PATCH", "/courses/:id/exam-result", async (req, env, p, body) => {
  await env.DB.prepare("UPDATE course_enrollments SET exam_score = ? WHERE course_id = ? AND user_id = ?").bind(body.exam_score, p.id, body.user_id).run();
  if (body.exam_score >= 60) {
    const certId = newId();
    const serial = `CR-${Date.now()}-${certId.slice(0, 6)}`;
    await env.DB.prepare(`INSERT INTO certificates (id, entity_id, user_id, source_type, source_id, serial_number, qr_code) VALUES (?, '${ENTITY}', ?, 'course', ?, ?, ?)`)
      .bind(certId, body.user_id, p.id, serial, `cert:${certId}`).run();
    await env.DB.prepare("UPDATE course_enrollments SET certificate_id = ? WHERE course_id = ? AND user_id = ?").bind(certId, p.id, body.user_id).run();
    return json({ ok: true, certificate_issued: true });
  }
  return json({ ok: true, certificate_issued: false });
}, { auth: true, roles: STAFF_ROLES });

// ================= المختصون والحجوزات =================
route("GET", "/specialists", async (req, env) => {
  const url = new URL(req.url);
  const specialty = url.searchParams.get("specialty");
  const city = url.searchParams.get("city");
  let sql = `SELECT u.id, u.full_name, u.avatar_url, sp.specialty, sp.city, sp.price_info, sp.bio, sp.rating_avg, sp.rating_count FROM specialist_profiles sp JOIN users u ON u.id = sp.user_id WHERE 1=1`;
  const bindings = [];
  if (specialty) { sql += " AND sp.specialty = ?"; bindings.push(specialty); }
  if (city) { sql += " AND sp.city = ?"; bindings.push(city); }
  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return json(results);
});
route("GET", "/specialists/:id", async (req, env, p) => {
  const profile = await env.DB.prepare("SELECT u.id, u.full_name, u.avatar_url, sp.* FROM specialist_profiles sp JOIN users u ON u.id = sp.user_id WHERE u.id = ?").bind(p.id).first();
  if (!profile) return err("المختص غير موجود", 404);
  const { results: availability } = await env.DB.prepare("SELECT * FROM specialist_availability WHERE specialist_id = ?").bind(p.id).all();
  return json({ ...profile, availability });
});
route("PUT", "/specialists/me/profile", async (req, env, p, body, user) => {
  await env.DB.prepare(`INSERT INTO specialist_profiles (user_id, specialty, city, price_info, bio) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET specialty=excluded.specialty, city=excluded.city, price_info=excluded.price_info, bio=excluded.bio`)
    .bind(user.sub, body.specialty, body.city ?? null, body.price_info ?? null, body.bio ?? null).run();
  return json({ ok: true });
}, { auth: true, roles: SPECIALIST_ROLES });
route("POST", "/specialists/:id/bookings", async (req, env, p, body, user) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO bookings (id, entity_id, user_id, specialist_id, requested_at, notes) VALUES (?, '${ENTITY}', ?, ?, ?, ?)`)
    .bind(id, user.sub, p.id, body.requested_at, body.notes ?? null).run();
  return json({ id, status: "pending" }, 201);
}, { auth: true });
route("PATCH", "/specialists/bookings/:bookingId", async (req, env, p, body) => {
  await env.DB.prepare("UPDATE bookings SET status = ? WHERE id = ?").bind(body.status, p.bookingId).run();
  return json({ ok: true });
}, { auth: true, roles: SPECIALIST_ROLES });
route("GET", "/specialists/me/bookings", async (req, env, p, body, user) => {
  const isSpecialist = SPECIALIST_ROLES.includes(user.role);
  const { results } = await env.DB.prepare(isSpecialist ? "SELECT * FROM bookings WHERE specialist_id = ? ORDER BY requested_at DESC" : "SELECT * FROM bookings WHERE user_id = ? ORDER BY requested_at DESC").bind(user.sub).all();
  return json(results);
}, { auth: true });
route("POST", "/specialists/bookings/:bookingId/review", async (req, env, p, body) => {
  await env.DB.prepare("INSERT INTO specialist_reviews (id, booking_id, rating, comment) VALUES (?, ?, ?, ?)").bind(newId(), p.bookingId, body.rating, body.comment ?? null).run();
  return json({ ok: true });
}, { auth: true });

// ================= المحتوى =================
route("GET", "/content", async (req, env) => {
  const url = new URL(req.url);
  const type = url.searchParams.get("type");
  const category = url.searchParams.get("category");
  const q = url.searchParams.get("q");
  let sql = "SELECT * FROM content_items WHERE status = 'published'";
  const bindings = [];
  if (type) { sql += " AND type = ?"; bindings.push(type); }
  if (category) { sql += " AND category = ?"; bindings.push(category); }
  if (q) { sql += " AND (title LIKE ? OR summary LIKE ?)"; bindings.push(`%${q}%`, `%${q}%`); }
  sql += " ORDER BY created_at DESC LIMIT 50";
  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return json(results);
});
route("GET", "/content/me/favorites", async (req, env, p, body, user) => {
  const { results } = await env.DB.prepare("SELECT ci.* FROM content_favorites f JOIN content_items ci ON ci.id = f.content_id WHERE f.user_id = ?").bind(user.sub).all();
  return json(results);
}, { auth: true });
route("GET", "/content/:id", async (req, env, p) => {
  const item = await env.DB.prepare("SELECT * FROM content_items WHERE id = ?").bind(p.id).first();
  if (!item) return err("المحتوى غير موجود", 404);
  await env.DB.prepare("UPDATE content_items SET views = views + 1 WHERE id = ?").bind(p.id).run();
  return json(item);
});
route("POST", "/content", async (req, env, p, body, user) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO content_items (id, entity_id, type, title, summary, body, file_url, cover_image_url, category, tags, status, created_by) VALUES (?, '${ENTITY}', ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)`)
    .bind(id, body.type, body.title, body.summary ?? null, body.body ?? null, body.file_url ?? null, body.cover_image_url ?? null, body.category ?? null, body.tags ?? null, user.sub).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });
route("POST", "/content/:id/favorite", async (req, env, p, body, user) => {
  await env.DB.prepare("INSERT OR IGNORE INTO content_favorites (content_id, user_id) VALUES (?, ?)").bind(p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });

// ================= المنتدى =================
route("GET", "/forum/posts", async (req, env) => {
  const { results } = await env.DB.prepare(`SELECT p.*, u.full_name, u.avatar_url,
    (SELECT COUNT(*) FROM forum_likes WHERE post_id = p.id) as likes_count,
