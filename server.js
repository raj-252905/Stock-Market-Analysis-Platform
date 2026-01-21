import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

dotenv.config({ path: [".env.local", ".env"] });

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("❌ FATAL: JWT_SECRET is not defined");
  process.exit(1);
}

app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));

const corsOptions = {
  origin: [
    "http://localhost:5174",
    "http://127.0.0.1:5174",
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  optionsSuccessStatus: 200,
};
app.use(cors());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

const connectWithRetry = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
    });
    console.log("✅ Connected to MongoDB");
  } catch (err) {
    console.error("MongoDB connection error:", err.message);
    setTimeout(connectWithRetry, 5000);
  }
};
connectWithRetry();

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true, maxlength: 50 },
  lastName: { type: String, required: true, trim: true, maxlength: 50 },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
      message: "Invalid email format",
    },
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: [/^[a-zA-Z0-9_]+$/, "Username can only contain letters, numbers, and underscores"],
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false, 
  },
  mobile: {
    type: String,
    required: true,
    validate: {
      validator: (mobile) => /^[0-9]{10}$/.test(mobile),
      message: "Mobile must be 10 digits",
    },
  },
  isAdmin: { type: Boolean, default: false },
  countryCode: { type: String, default: "+91", trim: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model("createaccounts", userSchema);

app.get("/api/health", (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
  res.json({
    status: "OK",
    db: dbStatus,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.post("/api/signup", authLimiter, async (req, res) => {
  try {
    const { firstName, lastName, email, username, password, mobile, isAdmin } = req.body;

    if (!firstName || !lastName || !email || !username || !password || !mobile) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: "User already exists." });
    }

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      username,
      password,
      mobile,
      isAdmin: !!isAdmin,
    });

    const token = jwt.sign(
      { userId: newUser._id, isAdmin: newUser.isAdmin },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    const userResponse = newUser.toObject();
    delete userResponse.password;

    res.status(201).json({
      success: true,
      message: "User registered successfully.",
      user: userResponse,
      token,
    });

  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Registration failed.", details: err.message });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const { username, password, userType } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }

    const user = await User.findOne({ username }).select("+password");
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    if (userType && ((userType === "admin" && !user.isAdmin) || (userType === "user" && user.isAdmin))) {
      return res.status(403).json({ error: `Account is not a ${userType} account.` });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    const userResponse = user.toObject();
    delete userResponse.password;

    res.json({
      success: true,
      message: "Login successful.",
      user: userResponse,
      token,
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Authentication failed.", details: err.message });
  }
});

app.get("/api/protected", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) return res.status(404).json({ error: "User not found." });

    res.json({
      message: "Protected route accessed successfully.",
      user,
    });

  } catch (err) {
    console.error("Protected route error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication required." });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        error: "Invalid token.",
        details: err.message.includes("expired") ? "Token has expired" : "Invalid token.",
      });
    }
    req.user = decoded;
    next();
  });
}

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found.", requestedUrl: req.originalUrl });
});

app.use((err, req, res, next) => {
  console.error("Unhandled server error:", err);
  res.status(500).json({
    error: "Internal server error.",
    details: err.message,
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running: http://localhost:${PORT}`);
  console.log(`📡 Available endpoints:
  - GET  /api/health
  - POST /api/signup
  - POST /api/login
  - GET  /api/protected`);
});
