// GSR Dashboard — server-side PIN gate + log login ke Cloudflare D1
// Konten dashboard TIDAK dikirim ke browser sampai PIN benar.
// Ganti PIN: edit array PINS di bawah, lalu commit (Cloudflare auto-deploy).
const PINS = ["56411", "55582"];
const COOKIE = "gsr_gate";
const TOKEN = "ok-9f3a7c21e8b45d6072a1"; // rahasia server; jangan disebar
const MAXAGE = 60 * 60 * 24 * 30;        // sesi diingat 30 hari

function page(err) {
  return `<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GSR Dashboard</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#0f172a,#1e293b);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.card{background:#fff;border-radius:18px;padding:38px 34px;width:min(92vw,360px);
box-shadow:0 24px 60px rgba(0,0,0,.4);text-align:center}
h2{margin:6px 0 2px;font-size:22px;color:#0f172a}
p{margin:0 0 20px;color:#64748b;font-size:13px}
input{width:100%;padding:14px;border:1.5px solid #cbd5e1;border-radius:10px;font-size:20px;
text-align:center;letter-spacing:6px;outline:none;margin-bottom:6px}
input:focus{border-color:#2563eb}
.err{min-height:18px;color:#dc2626;font-size:12.5px;margin-bottom:10px}
button{width:100%;padding:13px;border:none;border-radius:10px;background:#2563eb;color:#fff;
font-size:15px;font-weight:600;cursor:pointer}
.logo{width:70px;height:70px;margin:0 auto 12px;border-radius:16px;background:#0f172a;
display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:22px}
</style></head><body>
<div class="card">
  <div class="logo">GSR</div>
  <h2>GSR Dashboard</h2>
  <p>Masukkan PIN untuk membuka</p>
  <form method="POST" action="/">
    <input name="pin" type="password" inputmode="numeric" autocomplete="off" autofocus placeholder="• • • • •">
    <div class="err">${err ? "PIN salah, coba lagi." : ""}</div>
    <button type="submit">Buka Dashboard</button>
  </form>
</div></body></html>`;
}

// Catat login sukses ke D1 (kalau binding DB ada). Gagal-nya diam, nggak ganggu login.
async function logLogin(env, request, pin) {
  try {
    if (!env || !env.DB) return;
    const cf = request.cf || {};
    await env.DB.prepare(
      "INSERT INTO logins (waktu, pin, ip, negara, kota, device) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(
      new Date().toISOString(),
      pin,
      request.headers.get("CF-Connecting-IP") || "",
      cf.country || "",
      cf.city || "",
      request.headers.get("User-Agent") || ""
    ).run();
  } catch (e) { /* abaikan */ }
}

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);
  const cookies = request.headers.get("Cookie") || "";
  const authed = cookies.split(/;\s*/).some(c => c === COOKIE + "=" + TOKEN);

  // Logout
  if (url.pathname === "/logout") {
    const h = new Headers();
    h.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    h.set("Location", "/");
    return new Response(null, { status: 302, headers: h });
  }

  if (authed) return next();

  // Submit PIN
  if (request.method === "POST") {
    const form = await request.formData();
    const pin = (form.get("pin") || "").toString().trim();
    if (PINS.includes(pin)) {
      context.waitUntil(logLogin(env, request, pin)); // catat di background
      const h = new Headers();
      h.append("Set-Cookie", `${COOKIE}=${TOKEN}; Path=/; Max-Age=${MAXAGE}; HttpOnly; Secure; SameSite=Lax`);
      h.set("Location", "/");
      return new Response(null, { status: 302, headers: h });
    }
    return new Response(page(true), { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  // Not authed → show login (dashboard NEVER served here)
  return new Response(page(false), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
