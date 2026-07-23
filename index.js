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
route("PATCH", "/workshops/:id", async (req, env, p, body) => {
  const fields = ["title", "description", "video_url", "cover_image_url", "start_at", "status"];
  const sets = fields.filter((f) => f in body);
  if (!sets.length) return err("لا توجد حقول للتحديث");
  await env.DB.prepare(`UPDATE workshops SET ${sets.map((f) => f + " = ?").join(", ")} WHERE id = ?`).bind(...sets.map((f) => body[f]), p.id).run();
  return json({ ok: true });
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
route("PATCH", "/courses/:id", async (req, env, p, body) => {
  const fields = ["title", "description", "cover_image_url", "is_free", "has_exam", "status"];
  const sets = fields.filter((f) => f in body);
  if (!sets.length) return err("لا توجد حقول للتحديث");
  await env.DB.prepare(`UPDATE courses SET ${sets.map((f) => f + " = ?").join(", ")} WHERE id = ?`).bind(...sets.map((f) => body[f]), p.id).run();
  return json({ ok: true });
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
route("PATCH", "/content/:id", async (req, env, p, body) => {
  const fields = ["title", "summary", "body", "file_url", "cover_image_url", "category", "tags", "status"];
  const sets = fields.filter((f) => f in body);
  if (!sets.length) return err("لا توجد حقول للتحديث");
  await env.DB.prepare(`UPDATE content_items SET ${sets.map((f) => f + " = ?").join(", ")} WHERE id = ?`).bind(...sets.map((f) => body[f]), p.id).run();
  return json({ ok: true });
}, { auth: true, roles: STAFF_ROLES });
route("POST", "/content/:id/favorite", async (req, env, p, body, user) => {
  await env.DB.prepare("INSERT OR IGNORE INTO content_favorites (content_id, user_id) VALUES (?, ?)").bind(p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });

// ================= المنتدى =================
route("GET", "/forum/posts", async (req, env) => {
  const { results } = await env.DB.prepare(`SELECT p.*, u.full_name, u.avatar_url,
    (SELECT COUNT(*) FROM forum_likes WHERE post_id = p.id) as likes_count,
    (SELECT COUNT(*) FROM forum_comments WHERE post_id = p.id) as comments_count
    FROM forum_posts p JOIN users u ON u.id = p.user_id WHERE p.status = 'visible' ORDER BY p.created_at DESC LIMIT 50`).all();
  return json(results);
});
route("POST", "/forum/posts", async (req, env, p, body, user) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO forum_posts (id, entity_id, user_id, title, body) VALUES (?, '${ENTITY}', ?, ?, ?)`).bind(id, user.sub, body.title ?? null, body.body).run();
  return json({ id }, 201);
}, { auth: true });
route("GET", "/forum/posts/:id/comments", async (req, env, p) => {
  const { results } = await env.DB.prepare("SELECT cm.*, u.full_name, u.avatar_url FROM forum_comments cm JOIN users u ON u.id = cm.user_id WHERE cm.post_id = ? ORDER BY cm.created_at ASC").bind(p.id).all();
  return json(results);
});
route("POST", "/forum/posts/:id/comments", async (req, env, p, body, user) => {
  const id = newId();
  await env.DB.prepare("INSERT INTO forum_comments (id, post_id, user_id, body) VALUES (?, ?, ?, ?)").bind(id, p.id, user.sub, body.body).run();
  return json({ id }, 201);
}, { auth: true });
route("POST", "/forum/posts/:id/like", async (req, env, p, body, user) => {
  await env.DB.prepare("INSERT OR IGNORE INTO forum_likes (post_id, user_id) VALUES (?, ?)").bind(p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });
route("DELETE", "/forum/posts/:id/like", async (req, env, p, body, user) => {
  await env.DB.prepare("DELETE FROM forum_likes WHERE post_id = ? AND user_id = ?").bind(p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });
route("POST", "/forum/posts/:id/report", async (req, env, p, body, user) => {
  await env.DB.prepare("INSERT INTO forum_reports (id, post_id, reported_by, reason) VALUES (?, ?, ?, ?)").bind(newId(), p.id, user.sub, body.reason ?? null).run();
  return json({ ok: true });
}, { auth: true });
route("PATCH", "/forum/reports/:id", async (req, env, p, body) => {
  await env.DB.prepare("UPDATE forum_reports SET status = ? WHERE id = ?").bind(body.status, p.id).run();
  if (body.hide_post) {
    const report = await env.DB.prepare("SELECT post_id FROM forum_reports WHERE id = ?").bind(p.id).first();
    if (report?.post_id) await env.DB.prepare("UPDATE forum_posts SET status = 'hidden' WHERE id = ?").bind(report.post_id).run();
  }
  return json({ ok: true });
}, { auth: true, roles: STAFF_ROLES });

// ================= اسأل المختص =================
route("POST", "/questions", async (req, env, p, body) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO anonymous_questions (id, entity_id, question) VALUES (?, '${ENTITY}', ?)`).bind(id, body.question).run();
  return json({ id }, 201);
});
route("GET", "/questions/published", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT id, question, answer, created_at FROM anonymous_questions WHERE published = 1 ORDER BY created_at DESC LIMIT 50").all();
  return json(results);
});
route("GET", "/questions/pending", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM anonymous_questions WHERE status = 'pending' ORDER BY created_at ASC").all();
  return json(results);
}, { auth: true, roles: [...SPECIALIST_ROLES, ...STAFF_ROLES] });
route("PATCH", "/questions/:id/answer", async (req, env, p, body, user) => {
  await env.DB.prepare("UPDATE anonymous_questions SET answer = ?, answered_by = ?, status = 'answered', published = ? WHERE id = ?")
    .bind(body.answer, user.sub, body.publish ? 1 : 0, p.id).run();
  return json({ ok: true });
}, { auth: true, roles: [...SPECIALIST_ROLES, ...STAFF_ROLES] });

// ================= التحديات، نصيحة اليوم، الخدمات، الإشعارات، الشهادات =================
route("GET", "/challenges/current", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM weekly_challenges ORDER BY week_start DESC LIMIT 5").all();
  return json(results);
});
route("POST", "/challenges", async (req, env, p, body) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO weekly_challenges (id, entity_id, title, category, description, week_start) VALUES (?, '${ENTITY}', ?, ?, ?, ?)`)
    .bind(id, body.title, body.category ?? null, body.description ?? null, body.week_start).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });
route("POST", "/challenges/:id/complete", async (req, env, p, body, user) => {
  await env.DB.prepare(`INSERT INTO challenge_progress (id, challenge_id, user_id, completed, completed_at) VALUES (?, ?, ?, 1, datetime('now'))
    ON CONFLICT(challenge_id, user_id) DO UPDATE SET completed = 1, completed_at = datetime('now')`).bind(newId(), p.id, user.sub).run();
  await env.DB.prepare("UPDATE users SET points = points + 5 WHERE id = ?").bind(user.sub).run();
  return json({ ok: true });
}, { auth: true });

route("GET", "/daily-tip", async (req, env) => {
  const tip = await env.DB.prepare("SELECT * FROM daily_tips ORDER BY tip_date DESC LIMIT 1").first();
  return json(tip ?? null);
});
route("POST", "/daily-tip", async (req, env, p, body, user) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO daily_tips (id, entity_id, tip_text, tip_date, created_by) VALUES (?, '${ENTITY}', ?, ?, ?)`).bind(id, body.tip_text, body.tip_date, user.sub).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });

route("GET", "/services", async (req, env) => {
  const url = new URL(req.url);
  const wilaya = url.searchParams.get("wilaya");
  const category = url.searchParams.get("category");
  let sql = "SELECT * FROM service_directory WHERE 1=1";
  const bindings = [];
  if (wilaya) { sql += " AND wilaya = ?"; bindings.push(wilaya); }
  if (category) { sql += " AND category = ?"; bindings.push(category); }
  const { results } = await env.DB.prepare(sql).bind(...bindings).all();
  return json(results);
});
route("POST", "/services", async (req, env, p, body) => {
  const id = newId();
  await env.DB.prepare(`INSERT INTO service_directory (id, entity_id, category, name, wilaya, address, phone, lat, lng, notes) VALUES (?, '${ENTITY}', ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, body.category, body.name, body.wilaya ?? null, body.address ?? null, body.phone ?? null, body.lat ?? null, body.lng ?? null, body.notes ?? null).run();
  return json({ id }, 201);
}, { auth: true, roles: STAFF_ROLES });

route("GET", "/notifications", async (req, env, p, body, user) => {
  const { results } = await env.DB.prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").bind(user.sub).all();
  return json(results);
}, { auth: true });
route("PATCH", "/notifications/:id/read", async (req, env, p, body, user) => {
  await env.DB.prepare("UPDATE notifications SET read_at = datetime('now') WHERE id = ? AND user_id = ?").bind(p.id, user.sub).run();
  return json({ ok: true });
}, { auth: true });

route("GET", "/certificates/verify/:serial", async (req, env, p) => {
  const cert = await env.DB.prepare(`SELECT c.serial_number, c.source_type, c.issued_at, u.full_name FROM certificates c JOIN users u ON u.id = c.user_id WHERE c.serial_number = ?`).bind(p.serial).first();
  return cert ? json({ valid: true, ...cert }) : json({ valid: false }, 404);
});

route("GET", "/admin/stats", async (req, env) => {
  const db = env.DB;
  const [users, members, visitors, bookings, specialistsCount, articles, workshopsCount, coursesCount] = await Promise.all([
    db.prepare("SELECT COUNT(*) as n FROM users").first(),
    db.prepare("SELECT COUNT(*) as n FROM users WHERE role = 'member'").first(),
    db.prepare("SELECT COUNT(*) as n FROM users WHERE role = 'visitor'").first(),
    db.prepare("SELECT COUNT(*) as n FROM bookings").first(),
    db.prepare("SELECT COUNT(*) as n FROM specialist_profiles").first(),
    db.prepare("SELECT COUNT(*) as n FROM content_items WHERE type = 'article'").first(),
    db.prepare("SELECT COUNT(*) as n FROM workshops").first(),
    db.prepare("SELECT COUNT(*) as n FROM courses").first(),
  ]);
  const { results: topArticles } = await db.prepare("SELECT id, title, views FROM content_items WHERE type = 'article' ORDER BY views DESC LIMIT 5").all();
  return json({ total_users: users.n, members: members.n, visitors: visitors.n, bookings: bookings.n, specialists: specialistsCount.n, articles: articles.n, workshops: workshopsCount.n, courses: coursesCount.n, top_articles: topArticles });
}, { auth: true, roles: ADMIN_ROLES });

// ================= الواجهة الأمامية (مضمّنة داخل نفس الملف) =================
const HOME_HTML = `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Insight Club</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&family=IBM+Plex+Sans+Arabic:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--navy:#0B1F3A;--navy-2:#122A4F;--gold:#C9A227;--gold-soft:#E4C874;--ivory:#FAF7EF;--ink:#1B1B1B;--radius:14px}
[data-theme="dark"]{--ivory:#0E1626;--ink:#EDE9DD;--navy-2:#16294A}
*{box-sizing:border-box}body{margin:0;background:var(--ivory);color:var(--ink);font-family:"IBM Plex Sans Arabic","Cairo",sans-serif}
h1,h2,h3,.brand{font-family:"Cairo",sans-serif}
header{position:sticky;top:0;z-index:50;background:var(--navy);color:var(--ivory);padding:14px 20px;display:flex;align-items:center;justify-content:space-between}
.brand{font-weight:900;font-size:1.25rem;color:var(--gold-soft)}
.icon-btn{background:transparent;border:1px solid var(--gold-soft);color:var(--gold-soft);border-radius:999px;padding:6px 14px;cursor:pointer;font-family:inherit;font-size:.85rem}
.hero{background:linear-gradient(160deg,var(--navy) 0%,var(--navy-2) 100%);color:var(--ivory);padding:56px 20px 70px;text-align:center}
.hero h1{font-size:clamp(1.6rem,5vw,2.6rem);margin:0 0 14px}
.hero p{opacity:.85;max-width:560px;margin:0 auto 24px}
.btn{padding:12px 26px;border-radius:999px;font-weight:600;cursor:pointer;border:none;font-family:inherit}
.btn-gold{background:var(--gold);color:var(--navy)}
main{max-width:1000px;margin:0 auto;padding:0 20px}
section{padding:40px 0;border-bottom:1px solid rgba(11,31,58,.08)}
section h2{font-size:1.35rem;color:var(--navy)}
[data-theme="dark"] section h2{color:var(--gold-soft)}
.eyebrow{color:var(--gold);font-weight:700;font-size:.78rem}
.grid{display:grid;gap:16px;margin-top:20px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.card{background:var(--navy);color:var(--ivory);border-radius:var(--radius);padding:18px;border-inline-start:3px solid var(--gold)}
.card h3{margin:0 0 6px;font-size:1rem}.card p{margin:0;font-size:.88rem;opacity:.8}
.tip-box{background:var(--gold);color:var(--navy);border-radius:var(--radius);padding:18px 22px;font-weight:600}
.empty{opacity:.6;font-size:.9rem}
footer{background:var(--navy);color:var(--ivory);text-align:center;padding:26px 20px;font-size:.85rem}
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:100;padding:20px}
.modal-backdrop.open{display:flex}
.modal{background:var(--ivory);color:var(--ink);border-radius:var(--radius);padding:24px;max-width:360px;width:100%}
.modal input{width:100%;padding:10px;margin:6px 0;border-radius:8px;border:1px solid #ccc;font-family:inherit}
</style></head><body>
<header><div class="brand">Insight Club</div>
<div style="display:flex;gap:8px"><button class="icon-btn" onclick="toggleTheme()">🌓</button><button class="icon-btn" onclick="openAuth()">دخول</button></div></header>
<section class="hero"><h1>مساحتك للصحة النفسية والوقاية من الإدمان</h1>
<p>نادي Insight Club يرافق الشباب الجزائري عبر أنشطة توعوية، ورشات، دعم من مختصين، ومجتمع داعم.</p>
<button class="btn btn-gold" onclick="openAuth()">انضم كعضو</button></section>
<main>
<section><div class="eyebrow">اليوم</div><h2>نصيحة اليوم</h2><div id="tip" class="tip-box">جارٍ التحميل…</div></section>
<section><div class="eyebrow">قريبًا</div><h2>الأنشطة</h2><div id="activities" class="grid"></div></section>
<section><div class="eyebrow">تعلّم</div><h2>الورشات</h2><div id="workshops" class="grid"></div></section>
<section><div class="eyebrow">المكتبة</div><h2>المقالات والبودكاست</h2><div id="content" class="grid"></div></section>
<section><div class="eyebrow">دليل الخدمات</div><h2>المختصون</h2><div id="specialists" class="grid"></div></section>
<section><div class="eyebrow">هذا الأسبوع</div><h2>التحدي الأسبوعي</h2><div id="challenges" class="grid"></div></section>
</main>
<footer>نادي Insight Club — دار الشباب باش جراح — 0549112391</footer>
<div class="modal-backdrop" id="authModal"><div class="modal">
<h3 style="margin-top:0;color:var(--navy)">تسجيل الدخول / إنشاء حساب</h3>
<input id="fullname" placeholder="الاسم الكامل (عند إنشاء حساب)">
<input id="identifier" placeholder="البريد الإلكتروني أو الهاتف">
<input id="password" type="password" placeholder="كلمة المرور">
<div style="display:flex;gap:10px;margin-top:12px">
<button class="btn btn-gold" style="flex:1" onclick="login()">دخول</button>
<button class="btn" style="flex:1;border:1px solid var(--navy);color:var(--navy);background:transparent" onclick="registerUser()">حساب جديد</button>
</div><div style="text-align:center;margin-top:8px;opacity:.6;cursor:pointer" onclick="closeAuth()">إغلاق</div>
</div></div>
<script>
function toggleTheme(){const h=document.documentElement;const n=h.getAttribute('data-theme')==='dark'?'light':'dark';h.setAttribute('data-theme',n);localStorage.setItem('theme',n)}
(function(){const s=localStorage.getItem('theme');if(s)document.documentElement.setAttribute('data-theme',s)})();
function openAuth(){document.getElementById('authModal').classList.add('open')}
function closeAuth(){document.getElementById('authModal').classList.remove('open')}
async function api(path,opt={}){const t=localStorage.getItem('token');const h={'Content-Type':'application/json',...(opt.headers||{})};if(t)h['Authorization']='Bearer '+t;const r=await fetch(path,{...opt,headers:h});return r.ok?r.json():Promise.reject(await r.json().catch(()=>({})))}
function fv(id){return document.getElementById(id).value}
async function login(){try{const d=await api('/auth/login',{method:'POST',body:JSON.stringify({identifier:fv('identifier'),password:fv('password')})});localStorage.setItem('token',d.token);closeAuth();alert('مرحبًا بعودتك، '+d.user.full_name)}catch(e){alert(e.error||'تعذر تسجيل الدخول')}}
async function registerUser(){const idf=fv('identifier');const isEmail=idf.includes('@');try{const d=await api('/auth/register',{method:'POST',body:JSON.stringify({full_name:fv('fullname'),password:fv('password'),email:isEmail?idf:undefined,phone:!isEmail?idf:undefined})});localStorage.setItem('token',d.token);closeAuth();alert('تم إنشاء الحساب: '+d.user.full_name)}catch(e){alert(e.error||'تعذر إنشاء الحساب')}}
function card(t,d,m){return \`<div class="card"><h3>\${t}</h3><p>\${d||''}</p><div style="font-size:.78rem;color:var(--gold-soft);margin-top:8px">\${m||''}</div></div>\`}
function list(id,items,fn,empty){const el=document.getElementById(id);el.innerHTML=(items&&items.length)?items.map(fn).join(''):'<div class="empty">'+empty+'</div>'}
(async()=>{
try{const t=await api('/daily-tip');document.getElementById('tip').textContent=t?.tip_text||'لم تُنشر نصيحة اليوم بعد.'}catch{document.getElementById('tip').textContent='تعذر التحميل'}
try{list('activities',await api('/activities'),a=>card(a.title,a.description,new Date(a.start_at).toLocaleDateString('ar-DZ')),'لا توجد أنشطة حاليًا.')}catch{}
try{list('workshops',await api('/workshops'),w=>card(w.title,w.description,'شهادة عند 75٪ حضور'),'لا توجد ورشات حاليًا.')}catch{}
try{list('content',await api('/content'),c=>card(c.title,c.summary,c.type),'المكتبة فارغة حاليًا.')}catch{}
try{list('specialists',await api('/specialists'),s=>card(s.full_name,s.bio,s.specialty),'دليل المختصين فارغ حاليًا.')}catch{}
try{list('challenges',await api('/challenges/current'),ch=>card(ch.title,ch.description,ch.category||''),'لا يوجد تحدٍّ منشور بعد.')}catch{}
})();
</script></body></html>`;

// ================= لوحة الإدارة =================
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>لوحة إدارة Insight Club</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&family=IBM+Plex+Sans+Arabic:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--navy:#0B1F3A;--gold:#C9A227;--ivory:#FAF7EF;--ink:#1B1B1B}
*{box-sizing:border-box}body{margin:0;background:var(--ivory);color:var(--ink);font-family:"IBM Plex Sans Arabic","Cairo",sans-serif}
h1,h2,.brand{font-family:"Cairo",sans-serif}
header{background:var(--navy);color:var(--ivory);padding:16px 20px}
.brand{font-weight:900;font-size:1.2rem;color:var(--gold)}
main{max-width:700px;margin:0 auto;padding:16px}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
.tab{padding:8px 14px;border-radius:999px;border:1px solid var(--navy);background:transparent;color:var(--navy);font-family:inherit;font-size:.85rem;cursor:pointer}
.tab.active{background:var(--navy);color:var(--ivory)}
section.panel{display:none}
section.panel.active{display:block}
label{display:block;font-size:.82rem;margin:10px 0 4px;color:#555}
input,textarea,select{width:100%;padding:9px 10px;border-radius:8px;border:1px solid #ccc;font-family:inherit;font-size:.9rem}
textarea{min-height:70px}
.btn{margin-top:14px;padding:11px 20px;border-radius:999px;background:var(--gold);color:var(--navy);border:none;font-weight:700;cursor:pointer;font-family:inherit}
.item{background:#fff;border:1px solid #eee;border-radius:10px;padding:12px;margin-top:10px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.item .t{font-weight:600;font-size:.9rem}
.item .s{font-size:.75rem;color:#888}
.pub{padding:6px 12px;border-radius:999px;border:none;font-size:.78rem;cursor:pointer}
.pub.draft{background:#eee;color:#555}
.pub.published{background:#dff5e1;color:#1a7a34}
#loginBox{max-width:320px;margin:60px auto;background:#fff;padding:24px;border-radius:12px;border:1px solid #eee}
.msg{font-size:.8rem;color:#a33;margin-top:6px}
</style></head><body>
<header><div class="brand">لوحة إدارة Insight Club</div></header>
<div id="errBox" style="display:none;background:#a33;color:#fff;padding:10px 16px;font-size:.8rem;white-space:pre-wrap"></div>
<script>
window.onerror = function(msg, src, line){
  var b = document.getElementById('errBox');
  b.style.display = 'block';
  b.textContent = 'خطأ تقني: ' + msg + ' (سطر ' + line + ')';
  return false;
};
</script>
<div id="loginBox">
<h2 style="margin-top:0">تسجيل دخول فريق العمل</h2>
<label>البريد الإلكتروني أو الهاتف</label><input id="li">
<label>كلمة المرور</label><input id="lp" type="password">
<button class="btn" onclick="doLogin()">دخول</button>
<div class="msg" id="loginMsg"></div>
</div>
<main id="mainApp" style="display:none">
<div class="tabs">
<button class="tab active" data-t="tip">نصيحة اليوم</button>
<button class="tab" data-t="activities">الأنشطة</button>
<button class="tab" data-t="workshops">الورشات</button>
<button class="tab" data-t="content">المحتوى</button>
<button class="tab" data-t="challenges">التحديات</button>
<button class="tab" data-t="services">دليل الخدمات</button>
</div>

<section class="panel active" id="p-tip">
<label>نص النصيحة</label><textarea id="tip-text"></textarea>
<label>التاريخ</label><input id="tip-date" type="date">
<button class="btn" onclick="createTip()">نشر النصيحة</button>
</section>

<section class="panel" id="p-activities">
<label>العنوان</label><input id="ac-title">
<label>الوصف</label><textarea id="ac-desc"></textarea>
<label>نوع الحضور</label><select id="ac-mode"><option value="in_person">حضوري</option><option value="online">عن بعد</option></select>
<label>المكان</label><input id="ac-loc">
<label>تاريخ ووقت البدء</label><input id="ac-start" type="datetime-local">
<label>عدد المقاعد (اختياري)</label><input id="ac-cap" type="number">
<button class="btn" onclick="createItem('activities','ac')">إنشاء النشاط</button>
<div id="list-activities"></div>
</section>

<section class="panel" id="p-workshops">
<label>العنوان</label><input id="ws-title">
<label>الوصف</label><textarea id="ws-desc"></textarea>
<label>رابط الفيديو (اختياري)</label><input id="ws-video">
<label>تاريخ البدء</label><input id="ws-start" type="datetime-local">
<button class="btn" onclick="createItem('workshops','ws')">إنشاء الورشة</button>
<div id="list-workshops"></div>
</section>

<section class="panel" id="p-content">
<label>النوع</label><select id="ct-type"><option value="article">مقال</option><option value="video">فيديو</option><option value="podcast">بودكاست</option><option value="pdf">PDF</option><option value="infographic">إنفوغرافيك</option></select>
<label>العنوان</label><input id="ct-title">
<label>ملخص</label><textarea id="ct-summary"></textarea>
<label>رابط الملف/الفيديو (اختياري)</label><input id="ct-file">
<label>رابط صورة الغلاف (اختياري)</label><input id="ct-cover">
<button class="btn" onclick="createItem('content','ct')">إضافة للمكتبة</button>
<div id="list-content"></div>
</section>

<section class="panel" id="p-challenges">
<label>عنوان التحدي</label><input id="ch-title">
<label>التصنيف</label><select id="ch-cat"><option value="gratitude">الامتنان</option><option value="sleep">النوم</option><option value="sports">الرياضة</option><option value="reading">القراءة</option><option value="meditation">التأمل</option><option value="other">أخرى</option></select>
<label>الوصف</label><textarea id="ch-desc"></textarea>
<label>بداية الأسبوع</label><input id="ch-week" type="date">
<button class="btn" onclick="createChallenge()">نشر التحدي</button>
<div id="list-challenges"></div>
</section>

<section class="panel" id="p-services">
<label>التصنيف</label><select id="sv-cat">
<option value="psych_specialist">مختص نفسي</option><option value="psychiatrist">طبيب نفسي</option>
<option value="nutritionist">أخصائي تغذية</option><option value="sports_hall">قاعة رياضية</option>
<option value="addiction_treatment_center">مركز علاج إدمان</option><option value="support_association">جمعية دعم نفسي</option>
</select>
<label>الاسم</label><input id="sv-name">
<label>الولاية</label><input id="sv-wilaya">
<label>العنوان</label><input id="sv-addr">
<label>الهاتف</label><input id="sv-phone">
<button class="btn" onclick="createService()">إضافة للدليل</button>
<div id="list-services"></div>
</section>
</main>
<script>
function api(path,opt={}){const t=localStorage.getItem('token');const h={'Content-Type':'application/json',...(opt.headers||{})};if(t)h['Authorization']='Bearer '+t;return fetch(path,{...opt,headers:h}).then(async r=>r.ok?r.json():Promise.reject(await r.json().catch(()=>({}))))}
async function doLogin(){
  try{
    const d=await api('/auth/login',{method:'POST',body:JSON.stringify({identifier:document.getElementById('li').value,password:document.getElementById('lp').value})});
    if(!['committee_lead','manager','super_admin'].includes(d.user.role)){document.getElementById('loginMsg').textContent='هذا الحساب لا يملك صلاحية الوصول للوحة الإدارة.';return}
    localStorage.setItem('token',d.token);
    document.getElementById('loginBox').style.display='none';
    document.getElementById('mainApp').style.display='block';
    loadAll();
  }catch(e){document.getElementById('loginMsg').textContent=e.error||'بيانات الدخول غير صحيحة'}
}
document.querySelectorAll('.tab').forEach(btn=>btn.addEventListener('click',()=>{
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('p-'+btn.dataset.t).classList.add('active');
}));
async function createTip(){
  await api('/daily-tip',{method:'POST',body:JSON.stringify({tip_text:document.getElementById('tip-text').value,tip_date:document.getElementById('tip-date').value||new Date().toISOString().slice(0,10)})});
  alert('تم نشر نصيحة اليوم');document.getElementById('tip-text').value='';
}
async function createItem(type,prefix){
  const payload={};
  if(type==='activities'){payload.title=v(prefix+'-title');payload.description=v(prefix+'-desc');payload.mode=v(prefix+'-mode');payload.location=v(prefix+'-loc');payload.start_at=v(prefix+'-start');payload.capacity=v(prefix+'-cap')||null}
  if(type==='workshops'){payload.title=v(prefix+'-title');payload.description=v(prefix+'-desc');payload.video_url=v(prefix+'-video');payload.start_at=v(prefix+'-start')}
  if(type==='content'){payload.type=v(prefix+'-type');payload.title=v(prefix+'-title');payload.summary=v(prefix+'-summary');payload.file_url=v(prefix+'-file');payload.cover_image_url=v(prefix+'-cover')}
  try{
    const d=await api('/'+type,{method:'POST',body:JSON.stringify(payload)});
    await api('/'+type+'/'+d.id,{method:'PATCH',body:JSON.stringify({status:'published'})});
    alert('تم النشر بنجاح');
    refreshList(type);
  }catch(e){alert(e.error||'حدث خطأ')}
}
async function createChallenge(){
  try{
    await api('/challenges',{method:'POST',body:JSON.stringify({title:v('ch-title'),category:v('ch-cat'),description:v('ch-desc'),week_start:v('ch-week')||new Date().toISOString().slice(0,10)})});
    alert('تم نشر التحدي');refreshList('challenges');
  }catch(e){alert(e.error||'حدث خطأ')}
}
async function createService(){
  try{
    await api('/services',{method:'POST',body:JSON.stringify({category:v('sv-cat'),name:v('sv-name'),wilaya:v('sv-wilaya'),address:v('sv-addr'),phone:v('sv-phone')})});
    alert('تمت الإضافة للدليل');refreshList('services');
  }catch(e){alert(e.error||'حدث خطأ')}
}
function v(id){return document.getElementById(id).value}
async function refreshList(type){
  const map={activities:'/activities',workshops:'/workshops',content:'/content',challenges:'/challenges/current',services:'/services'};
  const el=document.getElementById('list-'+type);
  if(!el)return;
  try{
    const items=await api(map[type]);
    el.innerHTML=items.map(it=>\`<div class="item"><div><div class="t">\${it.title||it.name}</div><div class="s">\${it.status||''}</div></div>\${it.status?\`<button class="pub \${it.status}" onclick="togglePublish('\${type}','\${it.id}','\${it.status}')">\${it.status==='published'?'منشور ✓':'نشر الآن'}</button>\`:''}</div>\`).join('')||'<p style="opacity:.6">لا توجد عناصر بعد.</p>';
  }catch(e){}
}
async function togglePublish(type,id,current){
  const next=current==='published'?'draft':'published';
  await api('/'+type+'/'+id,{method:'PATCH',body:JSON.stringify({status:next})});
  refreshList(type);
}
function loadAll(){['activities','workshops','content','challenges','services'].forEach(refreshList)}
if(localStorage.getItem('token')){document.getElementById('loginBox').style.display='none';document.getElementById('mainApp').style.display='block';loadAll();}
<\/script></body></html>`;

// ================= المشغل الرئيسي =================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" } });
    }
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      return new Response(HOME_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    if (request.method === "GET" && url.pathname === "/admin") {
      return new Response(ADMIN_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    for (const r of routes) {
      if (r.method !== request.method) continue;
      const match = url.pathname.match(r.regex);
      if (!match) continue;
      const p = params(match, r.keys);
      let user = null;
      if (r.auth) {
        user = await getUser(request, env);
        if (!user) return err("غير مصرح - يلزم تسجيل الدخول", 401);
        if (r.roles && !r.roles.includes(user.role)) return err("لا تملك صلاحية الوصول لهذا المورد", 403);
      }
      let body = {};
      if (["POST", "PATCH", "PUT"].includes(request.method)) {
        try { body = await request.json(); } catch { body = {}; }
      }
      try {
        return await r.handler(request, env, p, body, user);
      } catch (e) {
        return err("حدث خطأ في الخادم: " + e.message, 500);
      }
    }
    return err("المسار غير موجود", 404);
  },
};
