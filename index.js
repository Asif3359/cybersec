const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const nodemailer = require("nodemailer");
const otpGenerator = require("otp-generator");

dotenv.config();

const app = express();

// SECURITY
app.use(helmet());
app.use(cors());
app.use(express.json());

// RATE LIMIT
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
  })
);

// EMAIL SETUP
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// OTP GENERATOR
function generateOTP() {
  return otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    specialChars: false
  });
}

// MongoDB
const { MongoClient, ServerApiVersion } = require("mongodb");

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.gvhiukk.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: ServerApiVersion.v1
});

let userCollection;

async function run() {
  await client.connect();
  const db = client.db("cyber_security");
  userCollection = db.collection("users");
  console.log("MongoDB Connected");
}
run();

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!email || !password || password.length < 6) {
    return res.status(400).send({ error: "Invalid input" });
  }

  const exists = await userCollection.findOne({ email });
  if (exists) return res.send({ error: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);

  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    failedAttempts: 0,
    lockUntil: null
  });

  res.send({ message: "User registered successfully" });
});

// ================= LOGIN (STEP 1) =================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await userCollection.findOne({ email });
  if (!user) return res.send({ error: "User not found" });

  // Lock check
  if (user.lockUntil && user.lockUntil > Date.now()) {
    return res.send({ error: "Account locked. Try later." });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    const attempts = (user.failedAttempts || 0) + 1;

    let update = { failedAttempts: attempts };

    if (attempts >= 3) {
      update.lockUntil = Date.now() + 10 * 60 * 1000;
      update.failedAttempts = 0;
    }

    await userCollection.updateOne({ email }, { $set: update });

    return res.send({ error: "Wrong password" });
  }

  // reset attempts
  await userCollection.updateOne(
    { email },
    { $set: { failedAttempts: 0 } }
  );

  // ===== OTP GENERATE =====
  const otp = generateOTP();

  await userCollection.updateOne(
    { email },
    {
      $set: {
        otp,
        otpExpire: Date.now() + 5 * 60 * 1000
      }
    }
  );

  // SEND EMAIL
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP is: ${otp}`
  });

  res.send({ message: "OTP sent to email" });
});

// ================= VERIFY OTP (STEP 2) =================
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  const user = await userCollection.findOne({ email });

  if (!user || user.otp !== otp) {
    return res.send({ error: "Invalid OTP" });
  }

  if (user.otpExpire < Date.now()) {
    return res.send({ error: "OTP expired" });
  }

  // clear OTP
  await userCollection.updateOne(
    { email },
    { $unset: { otp: "", otpExpire: "" } }
  );

  // JWT
  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.send({ message: "Login successful", token });
});

app.get("/", (req, res) => {
  res.send("Server Running Securely 🚀");
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});