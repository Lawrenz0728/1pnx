import { withSupabase } from "npm:@supabase/server@^1";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

export default {
  fetch: withSupabase({ auth: "publishable" }, async (req, ctx) => {
    if (req.method === "OPTIONS") {
      return new Response("ok", { headers: corsHeaders });
    }

    if (req.method !== "POST") {
      return new Response(
        JSON.stringify({ ok: false, message: "Method not allowed" }),
        { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    try {
      const { username, password, passcode } = await req.json();

      const cleanUsername = String(username || "").trim().toLowerCase();
      const cleanPassword = String(password || "");
      const cleanPasscode = String(passcode || "");

      if (!/^[a-z0-9_]{3,30}$/.test(cleanUsername)) {
        return new Response(
          JSON.stringify({ ok: false, message: "Username must be 3-30 characters and use only letters, numbers, or underscore." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      if (cleanPassword.length < 6) {
        return new Response(
          JSON.stringify({ ok: false, message: "Password must be at least 6 characters." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      if (!cleanPasscode) {
        return new Response(
          JSON.stringify({ ok: false, message: "Registration passcode is required." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // Check the registration passcode without exposing it to the browser.
      const { data: settings, error: settingsError } =
        await ctx.supabaseAdmin
          .from("registration_settings")
          .select("passcode")
          .eq("id", 1)
          .maybeSingle();

      if (settingsError) throw settingsError;

      if (!settings || settings.passcode !== cleanPasscode) {
        return new Response(
          JSON.stringify({ ok: false, message: "Invalid registration passcode." }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // Check whether the username already exists.
      const { data: existing, error: existingError } =
        await ctx.supabaseAdmin
          .from("profiles")
          .select("id")
          .eq("username", cleanUsername)
          .maybeSingle();

      if (existingError) throw existingError;

      if (existing) {
        return new Response(
          JSON.stringify({ ok: false, message: "That username is already in use." }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // Supabase Auth still needs an identifier. This internal address is never
      // shown to or requested from the user, and admin.createUser does not send
      // a confirmation email.
      const internalEmail = `${cleanUsername}@1pnx.com`;

      const { data: created, error: createError } =
        await ctx.supabaseAdmin.auth.admin.createUser({
          email: internalEmail,
          password: cleanPassword,
          email_confirm: true,
          user_metadata: { username: cleanUsername },
        });

      if (createError) throw createError;

      if (!created.user) {
        throw new Error("Supabase did not return the new user.");
      }

      const { error: profileError } =
        await ctx.supabaseAdmin
          .from("profiles")
          .insert({
            id: created.user.id,
            username: cleanUsername,
          });

      if (profileError) {
        await ctx.supabaseAdmin.auth.admin.deleteUser(created.user.id);
        throw profileError;
      }

      return new Response(
        JSON.stringify({ ok: true, username: cleanUsername }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    } catch (error) {
      console.error(error);
      return new Response(
        JSON.stringify({ ok: false, message: error?.message || "Unable to create account." }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
  }),
};
