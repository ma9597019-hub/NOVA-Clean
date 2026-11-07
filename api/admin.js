// api/admin.js — Vercel Serverless Function
// يتعامل مع عمليات Supabase Admin (تغيير كلمة المرور، إيقاف/تفعيل الحساب)
// Service Role Key تبقى هنا على الخادم فقط — لا تظهر في المتصفح أبداً

import { createClient } from "@supabase/supabase-js";

// Super Admin المحمي — لا يمكن لأحد تعديل حسابه
const SUPER_ADMIN_NAME = "محمد علي عنتر جلال";

// الأدوار المسموح لها باستخدام هذه الـ API
const ALLOWED_ROLES = ["owner", "supervisor", "admin"];

export default async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  // 1. التحقق من الـ Access Token
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) return res.status(401).json({ error: "لا يوجد توكن — سجّل الدخول أولاً" });

  // 2. إنشاء Admin Client (Service Role)
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceKey) {
    return res.status(500).json({ error: "SUPABASE_URL أو SUPABASE_SERVICE_ROLE_KEY غير مضبوطة في Vercel" });
  }

  const adminClient = createClient(supabaseUrl, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  // 3. التحقق من هوية المستخدم الحالي عبر توكنه
  const { data: { user: caller }, error: authErr } =
    await adminClient.auth.getUser(token);
  if (authErr || !caller) return res.status(401).json({ error: "توكن غير صالح أو منتهي الصلاحية" });

  const callerRole = caller.app_metadata?.role || "";
  const callerName = caller.user_metadata?.username || "";

  if (!ALLOWED_ROLES.includes(callerRole)) {
    return res.status(403).json({ error: "ليس لديك صلاحية لتنفيذ هذه العمليات" });
  }

  const { action, targetName } = req.body;
  if (!action || !targetName) return res.status(400).json({ error: "action و targetName مطلوبان" });

  // 4. حماية Super Admin
  if (targetName === SUPER_ADMIN_NAME) {
    return res.status(403).json({ error: "لا يمكن تعديل حساب Super Admin" });
  }

  // 5. منع أي شخص من تعديل حسابه بنفسه (إلا owner)
  if (targetName === callerName && callerRole !== "owner") {
    return res.status(403).json({ error: "لا يمكنك تعديل حسابك بنفسك من هنا" });
  }

  // 6. إيجاد المستخدم المستهدف
  const { data: usersData, error: listErr } =
    await adminClient.auth.admin.listUsers({ perPage: 1000 });
  if (listErr) return res.status(500).json({ error: "تعذّر جلب قائمة المستخدمين: " + listErr.message });

  const targetUser = usersData.users.find(
    (u) => u.user_metadata?.username === targetName
  );
  if (!targetUser) {
    return res.status(404).json({ error: "المستخدم «" + targetName + "» غير موجود في Supabase Auth" });
  }

  // 7. تنفيذ العملية المطلوبة
  try {
    switch (action) {

      // ---- تغيير كلمة المرور ----
      case "set_password": {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) {
          return res.status(400).json({ error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
        }
        const { error } = await adminClient.auth.admin.updateUserById(
          targetUser.id,
          { password: newPassword }
        );
        if (error) throw error;
        return res.status(200).json({ ok: true, message: "تم تغيير كلمة مرور «" + targetName + "» بنجاح" });
      }

      // ---- إيقاف الحساب (Ban) ----
      case "ban": {
        const { error } = await adminClient.auth.admin.updateUserById(
          targetUser.id,
          { ban_duration: "876600h" } // ~100 سنة = إيقاف دائم
        );
        if (error) throw error;
        return res.status(200).json({ ok: true, message: "تم إيقاف حساب «" + targetName + "»" });
      }

      // ---- تفعيل الحساب (Unban) ----
      case "unban": {
        const { error } = await adminClient.auth.admin.updateUserById(
          targetUser.id,
          { ban_duration: "none" }
        );
        if (error) throw error;
        return res.status(200).json({ ok: true, message: "تم تفعيل حساب «" + targetName + "»" });
      }

      // ---- إرسال رابط إعادة تعيين كلمة المرور ----
      case "reset_password_email": {
        const userEmail = targetUser.email;
        if (!userEmail) {
          return res.status(400).json({ error: "المستخدم لا يملك بريد إلكتروني مسجّل" });
        }
        const { error } = await adminClient.auth.resetPasswordForEmail(userEmail);
        if (error) throw error;
        return res.status(200).json({ ok: true, message: "تم إرسال رابط إعادة التعيين إلى " + userEmail });
      }

      // ---- إجبار تغيير كلمة المرور في الدخول التالي ----
      case "force_password_change": {
        const { error } = await adminClient.auth.admin.updateUserById(
          targetUser.id,
          { user_metadata: { ...targetUser.user_metadata, force_password_change: true } }
        );
        if (error) throw error;
        return res.status(200).json({ ok: true, message: "سيُجبر «" + targetName + "» على تغيير كلمة المرور" });
      }

      // ---- جلب حالة الحساب ----
      case "get_status": {
        const isBanned = !!targetUser.banned_until &&
          new Date(targetUser.banned_until) > new Date();
        return res.status(200).json({
          ok: true,
          userId: targetUser.id,
          email: targetUser.email || null,
          isBanned,
          bannedUntil: targetUser.banned_until || null,
          lastSignIn: targetUser.last_sign_in_at || null,
          createdAt: targetUser.created_at || null,
          forcePasswordChange: targetUser.user_metadata?.force_password_change || false,
        });
      }

      default:
        return res.status(400).json({ error: "عملية غير معروفة: " + action });
    }
  } catch (err) {
    console.error("[admin API error]", action, targetName, err);
    return res.status(500).json({ error: err.message || "خطأ غير معروف في الخادم" });
  }
}
