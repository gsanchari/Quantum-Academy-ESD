import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

import { connectDB } from "./lib/db.js";
import userModel from "./Models/userModel.js";

dotenv.config();

// Setup __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App setup
const app = express();
const port = 3030;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session setup
app.use(session({
  secret: "google_oauth_secret",
  resave: false,
  saveUninitialized: true,
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connect
connectDB();

// Static frontend
const frontendPath = path.join(__dirname, "..", "..", "Frontend");
app.use(express.static(frontendPath));

// ==============================
// ✅ GOOGLE STRATEGY
// ==============================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // ✅ Must match .env and Google Console
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let user = await userModel.findOne({ email });

        if (!user) {
          user = await userModel.create({
            name: profile.displayName,
            email,
            username: profile.id,
            password: "GOOGLE_AUTH",
          });
        }

        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// Serialize/Deserialize
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await userModel.findById(id);
  done(null, user);
});

// ==============================
// 🚀 ROUTES
// ==============================
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "Index.html")));
app.get("/signup", (req, res) => res.sendFile(path.join(frontendPath, "signUp.html")));
app.get("/login", (req, res) => res.sendFile(path.join(frontendPath, "login.html")));

app.post("/signup", async (req, res) => {
  const { name, username, email, password } = req.body;

  if (!name || !username || !email || !password)
    return res.status(400).send("Please fill all fields");

  const existingUser = await userModel.findOne({ $or: [{ email }, { username }] });
  if (existingUser)
    return res.status(400).send("User already registered");

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);

  const newUser = await userModel.create({ name, username, email, password: hash });

  const token = jwt.sign({ email: newUser.email, userid: newUser._id }, process.env.JWT_SECRET_KEY);
  res.cookie("token", token, { httpOnly: true });
  res.redirect("/homepage");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await userModel.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).send("Invalid username or password");
  }

  const token = jwt.sign({ userid: user._id, username: user.username }, process.env.JWT_SECRET_KEY, {
    expiresIn: "1d",
  });

  res.cookie("token", token, { httpOnly: true });
  res.redirect("/homepage");
});

// ==============================
// 🌐 GOOGLE AUTH ROUTES
// ==============================
app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign(
      { userid: req.user._id, email: req.user.email },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1d" }
    );
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/homepage");
  }
);

// ==============================
// 🔒 AUTH MIDDLEWARE
// ==============================
function isLoggedIn(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = data;
    next();
  } catch (err) {
    res.clearCookie("token");
    return res.redirect("/login");
  }
}

// ==============================
// 🔐 PROTECTED ROUTES
// ==============================
app.get("/homepage", isLoggedIn, (req, res) => {
  res.sendFile(path.join(frontendPath, "Home.html"));
});

app.get("/course", isLoggedIn, (req, res) => {
  res.sendFile(path.join(frontendPath, "course.html"));
});

app.get("/priceing", isLoggedIn, (req, res) => {
  res.sendFile(path.join(frontendPath, "price.html"));
});

app.get("/aboutUS", isLoggedIn, (req, res) => {
  res.sendFile(path.join(frontendPath, "about-us.html"));
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.clearCookie("token");
    res.redirect("/login");
  });
});

// ==============================
// 🚀 START SERVER
// ==============================
app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
