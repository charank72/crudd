const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
mongoose.connect(
  "mongodb+srv://charan:Theja774@cluster0.1fhqwrq.mongodb.net/cccrrruuudd?retryWrites=true&w=majority"
);
const db = mongoose.connection;

// Models
const User = require("./models/user");

// Middleware
app.use(bodyParser.json());

// Routes
// Register a new user
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, "secret_key");
    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.userId = decoded.userId;
    req.role = decoded.role;
    next();
  });
};

// Get all users (accessible only to admin)
app.get("/api/users", verifyToken, async (req, res) => {
  try {
    if (req.role !== "admin") {
      return res.status(403).json({ message: "Forbidden" });
    }
    const users = await User.find({}, { password: 0 }); // Exclude password field
    res.status(200).json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Routes
// Update user by ID (accessible only to admin)
app.put('/api/users/:id', verifyToken, async (req, res) => {
  try {
    if (req.role !== 'admin') {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const { name, email, password, role } = req.body;
    await User.findByIdAndUpdate(req.params.id, { name, email, password, role });
    res.status(200).json({ message: 'User updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Delete user by ID (accessible only to admin)
app.delete('/api/users/:id', verifyToken, async (req, res) => {
  try {
    if (req.role !== 'admin') {
      return res.status(403).json({ message: 'Forbidden' });
    }
    await User.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
