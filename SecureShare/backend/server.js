require("dotenv").config();

const authRoutes = require("./routes/authRoutes");
const authMiddleware = require("./middleware/authMiddleware");
const roleMiddleware = require("./middleware/roleMiddleware");

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const connectDB = require("./config/database");
const fileRoutes = require("./routes/fileRoutes");

const app = express();

app.use(helmet());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://127.0.0.1:5500",
  }),
);

app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);

// Test route
app.get("/", (req, res) => {
  res.json({
    message: "SecureShare API is running successfully!",
  });
});

// Protected route: any authenticated user
app.get("/api/protected", authMiddleware, (req, res) => {
    res.json({
        message: "Authentication successful!",
        user: req.user
    });
});

// Admin-only route
app.get(
    "/api/admin",
    authMiddleware,
    roleMiddleware("admin"),
    (req, res) => {
        res.json({
            message: "Welcome, Admin!"
        });
    }
);

const PORT = process.env.PORT || 5000;

// Start the server
async function startServer() {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log("Server running at http://localhost:" + PORT);
    });
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  }
}

startServer();
