
// api/admin.js — Vercel Serverless Function

import { createClient } from "@supabase/supabase-js";

// Super Admin المحمي
const SUPER_ADMIN_NAME = "محمد علي عنتر جلال";

// الأدوار المسموح لها
const ALLOWED_ROLES = ["owner", "supervisor", "admin"];

export default async function handler(req, res) {

  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {

    // 1. التحقق من Access Token
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        error: "يجب تسجيل الدخول أولاً"
      });
    }

    // 2. قراءة إعدادات Supabase
    const supabaseUrl = process.env.SUPABASE_URL;

    // دعم المفتاح الموجود في Vercel
    const serviceKey =
      process.env.SUPABASE_SECRET_KEY ||
      process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !serviceKey) {
      console.error("Missing Supabase environment variables");

      return res.status(500).json({
        error: "إعدادات Supabase غير مكتملة في Vercel"
      });
    }

    // 3. إنشاء Admin Client
    const adminClient = createClient(
      supabaseUrl,
      serviceKey,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    );

    // 4. التحقق من هوية المشرف
    const {
      data: { user: caller },
      error: authErr
    } = await adminClient.auth.getUser(token);

    if (authErr || !caller) {
      return res.status(401).json({
        error: "جلسة الدخول غير صالحة"
      });
    }

    const callerRole = caller.app_metadata?.role || "";
    const callerName = caller.user_metadata?.username || "";

    if (!ALLOWED_ROLES.includes(callerRole)) {
      return res.status(403).json({
        error: "ليس لديك صلاحية لتنفيذ هذه العملية"
      });
    }

    // 5. قراءة الطلب
    const {
      action,
      targetName,
      userId,
      newPassword
    } = req.body || {};

    if (!action || (!userId && !targetName)) {
      return res.status(400).json({
        error: "بيانات العضو أو العملية غير مكتملة"
      });
    }

    // 6. جلب المستخدم المستهدف
    let targetUser;

    if (userId) {
      const { data, error } =
        await adminClient.auth.admin.getUserById(userId);

      if (error) throw error;

      targetUser = data.user;
    } else {
      const { data, error } =
        await adminClient.auth.admin.listUsers({
          page: 1,
          perPage: 1000
        });

      if (error) throw error;

      targetUser = data.users.find(
        user => user.user_metadata?.username === targetName
      );
    }

    if (!targetUser) {
      return res.status(404).json({
        error: "العضو غير موجود"
      });
    }

    const actualName =
      targetUser.user_metadata?.username || "";

    // 7. حماية Super Admin
    if (actualName === SUPER_ADMIN_NAME) {
      return res.status(403).json({
        error: "لا يمكن تعديل حساب Super Admin"
      });
    }

    // 8. منع تعديل الحساب الشخصي
    if (
      targetUser.id === caller.id &&
      callerRole !== "owner"
    ) {
      return res.status(403).json({
        error: "لا يمكنك تعديل حسابك من هذه اللوحة"
      });
    }

    // 9. تنفيذ العمليات
    switch (action) {

      // تغيير كلمة المرور
      case "set_password": {

        if (
          typeof newPassword !== "string" ||
          newPassword.length < 8
        ) {
          return res.status(400).json({
            error: "كلمة المرور يجب أن تكون 8 أحرف على الأقل"
          });
        }

        const { error } =
          await adminClient.auth.admin.updateUserById(
            targetUser.id,
            { password: newPassword }
          );

        if (error) throw error;

        return res.status(200).json({
          ok: true,
          message: "تم تغيير كلمة المرور بنجاح"
        });
      }

      // إيقاف الحساب
      case "ban": {

        const { error } =
          await adminClient.auth.admin.updateUserById(
            targetUser.id,
            { ban_duration: "876600h" }
          );

        if (error) throw error;

        return res.status(200).json({
          ok: true,
          message: "تم إيقاف الحساب بنجاح"
        });
      }

      // إعادة تفعيل الحساب
      case "unban": {

        const { error } =
          await adminClient.auth.admin.updateUserById(
            targetUser.id,
            { ban_duration: "none" }
          );

        if (error) throw error;

        return res.status(200).json({
          ok: true,
          message: "تم تفعيل الحساب بنجاح"
        });
      }

      // إرسال رابط استعادة كلمة المرور
      case "reset_password_email": {

        if (!targetUser.email) {
          return res.status(400).json({
            error: "لا يوجد بريد إلكتروني لهذا العضو"
          });
        }

        const { error } =
          await adminClient.auth.resetPasswordForEmail(
            targetUser.email
          );

        if (error) throw error;

        return res.status(200).json({
          ok: true,
          message: "تم إرسال رابط استعادة كلمة المرور"
        });
      }

      // إجبار تغيير كلمة المرور
      case "force_password_change": {

        const { error } =
          await adminClient.auth.admin.updateUserById(
            targetUser.id,
            {
              user_metadata: {
                ...targetUser.user_metadata,
                force_password_change: true
              }
            }
          );

        if (error) throw error;

        return res.status(200).json({
          ok: true,
          message: "تم تفعيل إجبار تغيير كلمة المرور"
        });
      }

      // عرض حالة الحساب
      case "get_status": {

        const isBanned =
          !!targetUser.banned_until &&
          new Date(targetUser.banned_until) > new Date();

        return res.status(200).json({
          ok: true,
          userId: targetUser.id,
          email: targetUser.email || null,
          isBanned,
          bannedUntil: targetUser.banned_until || null,
          lastSignIn: targetUser.last_sign_in_at || null,
          createdAt: targetUser.created_at || null,
          forcePasswordChange:
            !!targetUser.user_metadata?.force_password_change
        });
      }

      default:

        return res.status(400).json({
          error: "عملية غير معروفة"
        });
    }

  } catch (err) {

    console.error("[admin API error]", err);

    return res.status(500).json({
      error: "حدث خطأ أثناء تنفيذ العملية"
    });
  }
}
