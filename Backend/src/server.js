import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { connectDB } from "./lib/db.js";
import userModel from "./Models/userModel.js";

dotenv.config();

// Setup __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App setup
const app = express();
const port = 3030;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form data
app.use(cookieParser());

// Connect to MongoDB
connectDB();

// Frontend path
const frontendPath = path.join(__dirname, '..', '..', 'Frontend');
app.use(express.static(frontendPath));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'Index.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(frontendPath, 'signUp.html'));
});

app.post('/signup', async (req, res) => {
  const { name, username, email, password } = req.body;

  // Validate input
  if (!name || !username || !email || !password) {
    return res.status(400).send("Please fill all fields");
  }

  // Check if user exists
  const existingUser = await userModel.findOne({ $or: [{ email }, { username }] });
  if (existingUser) {
    return res.status(400).send("User already registered");
  }

  // Create user
  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.status(500).send("Error generating salt");

    bcrypt.hash(password, salt, async (err, hash) => {
      if (err) return res.status(500).send("Error hashing password");

      const newUser = await userModel.create({
        name,
        username,
        email,
        password: hash,
      });

      const token = jwt.sign(
        { email: email, userid: newUser._id },
        process.env.JWT_SECRET_KEY
      );

      res.cookie("token", token, { httpOnly: true });
      res.redirect("/homepage");
    });
  });
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(frontendPath, 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await userModel.findOne({ username });
    if (!user) {
      return res.status(400).send("Invalid username or password");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid username or password");
    }

    const token = jwt.sign(
      { userid: user._id, username: user.username },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1d" }
    );

    res.cookie("token", token, { httpOnly: true });
    res.redirect("/homepage");
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});


app.get('/logout', (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

// Middleware to check if logged in
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

// Protected route
app.get('/homepage', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  res.sendFile(path.join(frontendPath, 'Home.html'));
});

app.get('/course', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  res.sendFile(path.join(frontendPath, 'course.html'));
});

app.get('/priceing', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  res.sendFile(path.join(frontendPath, 'price.html'));
});

app.get('/aboutUS', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  res.sendFile(path.join(frontendPath, 'about-us.html'));
});

// Start server
app.listen(port, () => {
  console.log(`✅ Server is running on http://localhost:${port}`);
});
