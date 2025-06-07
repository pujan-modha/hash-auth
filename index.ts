import { UserDatabase } from "./db";

const userDb = new UserDatabase();

// Deterministic email hashing for consistent user identification
async function createEmailHash(email: string): Promise<string> {
  const EMAIL_SALT =
    process.env.EMAIL_SALT || "fallback_salt_value_if_not_set_in_env";
  const normalizedEmail = email.toLowerCase().trim();

  // Create salted email string for hashing
  const saltedEmail = EMAIL_SALT + normalizedEmail + EMAIL_SALT;

  // Use SHA-256 for deterministic hashing
  const encoder = new TextEncoder();
  const data = encoder.encode(saltedEmail);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  // Convert to hex string
  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

// Parse JSON request body with error handling
async function parseRequestBody(request: Request): Promise<any> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// In-memory session management for authentication
const activeSessions = new Set<string>();

function createSessionToken(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

const server = Bun.serve({
  port: 5000,
  async fetch(request) {
    const url = new URL(request.url);
    const method = request.method;

    // Configure CORS headers for cross-origin requests
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (method === "OPTIONS") {
      return new Response(null, { status: 200, headers: corsHeaders });
    }

    try {
      // Handle user registration requests
      if (url.pathname === "/register" && method === "POST") {
        const requestBody = await parseRequestBody(request);
        if (!requestBody?.email || !requestBody?.password) {
          return new Response(
            JSON.stringify({ error: "Email and password required" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        console.log(`Registration request received for: ${requestBody.email}`);

        // Generate deterministic hash from email for user identification
        const emailHash = await createEmailHash(requestBody.email);

        // Hash password with secure random salt
        const passwordHash = await Bun.password.hash(requestBody.password);

        // Check for existing user with same email
        const existingUser = userDb.getUserByEmailHash(emailHash);
        if (existingUser) {
          console.log(
            `Registration denied - email already registered: ${requestBody.email}`
          );
          return new Response(
            JSON.stringify({ error: "User already exists" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // Create new user record in database
        const result = userDb.addUser(emailHash, passwordHash);
        console.log(
          `User registration successful: ${requestBody.email} (ID: ${result.lastInsertRowid})`
        );

        // Create authenticated session for new user
        const sessionToken = createSessionToken();
        activeSessions.add(sessionToken);

        return new Response(
          JSON.stringify({
            success: true,
            message: "User registered successfully",
            sessionId: sessionToken,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Handle user login requests
      if (url.pathname === "/login" && method === "POST") {
        const requestBody = await parseRequestBody(request);
        if (!requestBody?.email || !requestBody?.password) {
          return new Response(
            JSON.stringify({ error: "Email and password required" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        console.log(`Login attempt for user: ${requestBody.email}`);

        // Generate deterministic hash to locate user record
        const emailHash = await createEmailHash(requestBody.email);
        const user = userDb.getUserByEmailHash(emailHash);

        if (!user) {
          console.log(`Login failed - user not found: ${requestBody.email}`);
          return new Response(
            JSON.stringify({ error: "Invalid credentials" }),
            {
              status: 401,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // Verify provided password against stored hash
        const isPasswordValid = await Bun.password.verify(
          requestBody.password,
          (user as any).password_hash
        );

        if (!isPasswordValid) {
          console.log(
            `Login failed - incorrect password: ${requestBody.email}`
          );
          return new Response(
            JSON.stringify({ error: "Invalid credentials" }),
            {
              status: 401,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // Create authenticated session for user
        const sessionToken = createSessionToken();
        activeSessions.add(sessionToken);

        console.log(`Login successful for user: ${requestBody.email}`);

        return new Response(
          JSON.stringify({
            success: true,
            message: "Login successful",
            sessionId: sessionToken,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Handle protected user list requests
      if (url.pathname === "/users" && method === "GET") {
        const sessionToken = request.headers
          .get("authorization")
          ?.replace("Bearer ", "");

        if (!sessionToken || !activeSessions.has(sessionToken)) {
          return new Response(
            JSON.stringify({ error: "Authentication required" }),
            {
              status: 401,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        const allUsers = userDb.getAllUsers();
        console.log(`User list requested - Total users: ${allUsers.length}`);

        return new Response(
          JSON.stringify({
            success: true,
            message:
              "All users retrieved (showing hashed data for security proof)",
            users: allUsers,
            total_users: allUsers.length,
            security_note:
              "Emails: SHA-256 + deterministic salt, Passwords: Argon2id + random salt",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Handle password reset requests
      if (url.pathname === "/reset-password" && method === "POST") {
        const sessionToken = request.headers
          .get("authorization")
          ?.replace("Bearer ", "");

        if (!sessionToken || !activeSessions.has(sessionToken)) {
          return new Response(
            JSON.stringify({ error: "Authentication required" }),
            {
              status: 401,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        const requestBody = await parseRequestBody(request);
        if (
          !requestBody?.email ||
          !requestBody?.currentPassword ||
          !requestBody?.newPassword
        ) {
          return new Response(
            JSON.stringify({
              error: "Email, current password, and new password required",
            }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        console.log(`Password reset request for user: ${requestBody.email}`);

        // Locate user record using deterministic email hash
        const emailHash = await createEmailHash(requestBody.email);
        const user = userDb.getUserByEmailHash(emailHash);

        if (!user) {
          console.log(
            `Password reset failed - user not found: ${requestBody.email}`
          );
          return new Response(JSON.stringify({ error: "User not found" }), {
            status: 404,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        // Verify current password before allowing reset
        const isCurrentPasswordValid = await Bun.password.verify(
          requestBody.currentPassword,
          (user as any).password_hash
        );

        if (!isCurrentPasswordValid) {
          console.log(
            `Password reset failed - incorrect current password: ${requestBody.email}`
          );
          return new Response(
            JSON.stringify({ error: "Current password is incorrect" }),
            {
              status: 401,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // Generate new password hash and update database
        const newPasswordHash = await Bun.password.hash(
          requestBody.newPassword
        );
        userDb.updatePassword(emailHash, newPasswordHash);

        console.log(`Password reset completed for user: ${requestBody.email}`);

        return new Response(
          JSON.stringify({
            success: true,
            message: "Password updated successfully",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Handle user logout requests
      if (url.pathname === "/logout" && method === "POST") {
        const sessionToken = request.headers
          .get("authorization")
          ?.replace("Bearer ", "");

        if (sessionToken && activeSessions.has(sessionToken)) {
          activeSessions.delete(sessionToken);
          console.log(`User logout completed successfully`);
          return new Response(
            JSON.stringify({
              success: true,
              message: "Logged out successfully",
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        return new Response(
          JSON.stringify({ error: "No active session found" }),
          {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Development endpoint for testing email hash consistency
      if (url.pathname === "/debug/test-hash" && method === "POST") {
        const requestBody = await parseRequestBody(request);
        if (!requestBody?.email) {
          return new Response(JSON.stringify({ error: "Email required" }), {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          });
        }

        const firstHash = await createEmailHash(requestBody.email);
        const secondHash = await createEmailHash(requestBody.email);
        const upperCaseHash = await createEmailHash(
          requestBody.email.toUpperCase()
        );

        return new Response(
          JSON.stringify({
            email: requestBody.email,
            hash1: firstHash,
            hash2: secondHash,
            hash3: upperCaseHash,
            same_email_same_hash: firstHash === secondHash,
            case_insensitive: firstHash === upperCaseHash,
            deterministic:
              firstHash === secondHash && secondHash === upperCaseHash,
            message:
              firstHash === secondHash && secondHash === upperCaseHash
                ? "Email hashing is working correctly"
                : "Email hashing has issues",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // API information and documentation endpoint
      if (url.pathname === "/" && method === "GET") {
        return new Response(
          JSON.stringify({
            message: "Secure Authentication API",
            version: "1.0.0",
            security: {
              email_hashing: "SHA-256 with deterministic salt",
              password_hashing: "Argon2id with random salt",
              duplicate_prevention: "Enabled via deterministic email hashing",
            },
            endpoints: {
              "POST /register": "Register new user (email, password)",
              "POST /login": "Login user (email, password)",
              "GET /users":
                "Get all users - protected (Authorization: Bearer <sessionId>)",
              "POST /reset-password":
                "Reset password - protected (email, currentPassword, newPassword)",
              "POST /logout": "Logout user - protected",
              "POST /debug/test-hash": "Test email hashing - development only",
            },
            example_usage: {
              register:
                'POST /register with {"email": "user@example.com", "password": "securepass123"}',
              login:
                'POST /login with {"email": "user@example.com", "password": "securepass123"}',
              protected_request:
                "Add header: Authorization: Bearer <sessionId_from_login>",
            },
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Return 404 for unrecognized routes
      return new Response(
        JSON.stringify({
          error: "Route not found",
          available_routes: [
            "/",
            "/register",
            "/login",
            "/users",
            "/reset-password",
            "/logout",
          ],
        }),
        {
          status: 404,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    } catch (error) {
      console.error("Server error occurred:", error);
      return new Response(
        JSON.stringify({
          error: "Internal server error",
          message: "Something went wrong on the server",
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }
  },
});

console.log(`Server running at http://localhost:${server.port}`);
console.log(`API Documentation available at: http://localhost:${server.port}/`);
console.log(
  `Debug email hashing at: POST http://localhost:${server.port}/debug/test-hash`
);
console.log(`Database: users.db (SQLite)`);
console.log(`Security: Deterministic email hashing + Random password salting`);

// Environment variable check for production deployment
if (!process.env.EMAIL_SALT) {
  console.log(
    `Warning: Using fallback EMAIL_SALT. Set EMAIL_SALT environment variable in production!`
  );
}
