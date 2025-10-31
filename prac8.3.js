const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// Secret key for JWT
const SECRET_KEY = "my_super_secret_key_123";

// Hardcoded sample users with roles
const users = [
  { id: 1, username: "admin", password: "admin123", role: "Admin" },
  { id: 2, username: "mod", password: "mod123", role: "Moderator" },
  { id: 3, username: "user", password: "user123", role: "User" },
];

// =====================================
// LOGIN ROUTE
// =====================================
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Create JWT token with user role
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    token,
  });
});

// =====================================
// VERIFY TOKEN MIDDLEWARE
// =====================================
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "Token missing" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// =====================================
// ROLE AUTHORIZATION MIDDLEWARE
// =====================================
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: `Access denied: Requires one of these roles → ${allowedRoles.join(", ")}`,
      });
    }
    next();
  };
}

// =====================================
// PROTECTED ROUTES
// =====================================

// Admin-only route
app.get("/admin/dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({
    message: "Welcome to the Admin Dashboard!",
    user: req.user,
  });
});

// Moderator-only route
app.get(
  "/moderator/manage",
  verifyToken,
  authorizeRoles("Moderator", "Admin"), // both Admin & Moderator can access
  (req, res) => {
    res.json({
      message: "Welcome to the Moderator Management Page!",
      user: req.user,
    });
  }
);

// User route (accessible by all authenticated users)
app.get("/user/profile", verifyToken, authorizeRoles("User", "Moderator", "Admin"), (req, res) => {
  res.json({
    message: "Welcome to your User Profile!",
    user: req.user,
  });
});

// =====================================
// START SERVER
// =====================================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

