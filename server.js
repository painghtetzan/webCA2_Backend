require("dotenv").config();
console.log("DEBUG: GOOGLE_CLIENT_ID length is:", process.env.GOOGLE_CLIENT_ID ? process.env.GOOGLE_CLIENT_ID.length : "UNDEFINED");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const passport = require("passport")
const google = require("passport-google-oauth20").Strategy
const app = express();

// -------------------- Config --------------------
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const frontEndUrl = process.env.FRONTEND_URL
const backendUrl = process.env.BACKEND_URL


// -------------------- Middleware --------------------
app.use(express.json());
app.use(passport.initialize())
app.use(
  cors({
    origin: function (origin, cb) {
      
      if (!origin) return cb(null, true);

      
      const allowedOrigin = frontEndUrl
      
      
      const isLocal = origin.startsWith("http://localhost:");
      const isProduction = origin === allowedOrigin;

      if (isLocal || isProduction) {
        return cb(null, true);
      }
      
      return cb(new Error("CORS blocked: " + origin));
    },
    credentials: true, 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
// -------------------- Database Connection --------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "defaultdb",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Test database connection on startup
pool.getConnection()
  .then((connection) => {
    console.log('✓ Database Connected Successfully');
    console.log('Database:', process.env.DB_NAME);
    connection.release();
  })
  .catch((err) => {
    console.error('✗ Database Connection Error:', err.message);
    console.error('Check your .env file for correct DB credentials');
  });

// -------------------- Helpers --------------------
function safeUser(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    school: u.school,
    role: u.role,
  };
}

function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const [type, token] = header.split(" ");
    if (type !== "Bearer" || !token) {
      return res.status(401).json({ message: "Missing or invalid token" });
    }
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, role, email, name }
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };
}

// -------------------- Health / DB Test --------------------
app.get("/health", (req, res) => {
  res.json({ ok: true, message: "Backend is running" });
});

app.get("/db-test", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, message: "DB connection failed", error: err.message });
  }
});

// -------------------- AUTH --------------------
// POST /auth/register
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, school, role } = req.body;

    if (!name || !email || !password || !school || !role) {
      return res.status(400).json({ message: "Missing required fields" });
    }
    if (!["student", "lecturer"].includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    // Check existing user
    const [existing] = await pool.query("SELECT id FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      "INSERT INTO users (name, email, password, school, role) VALUES (?, ?, ?, ?, ?)",
      [name, email, passwordHash, school, role]
    );

    const user = { id: result.insertId, name, email, school, role };
    return res.status(201).json({ message: "Registered successfully", user });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Register failed", error: err.message });
  }
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing email or password" });

    const [rows] = await pool.query("SELECT * FROM users WHERE email = ? LIMIT 1", [email]);
    if (rows.length === 0) return res.status(401).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({ message: "Login successful", token, user: safeUser(user) });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Login failed", error: err.message });
  }
});

//Google OAuth 

app.get('/auth/google', passport.authenticate('google',{scope:["profile","email"]}))


passport.use(new google({
  clientID:process.env.GOOGLE_CLIENT_ID,
  clientSecret:process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:`${backendUrl}/auth/google/register`,
  userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
},
  async(accessToken,refreshToken,profile,cb) =>{
    try{
      const [exitingUser] = await pool.query("SELECT * FROM users WHERE email=?",[profile.emails[0].value])
      if(exitingUser.length<1){
        const email = profile.emails[0].value

        return cb(null,{email,isNew:true})
        
      }else{
        const euser = exitingUser[0]
        const user = safeUser(euser)
        const token = jwt.sign({ id: euser.id, role: euser.role, email: euser.email, name: euser.name,school:euser.school },JWT_SECRET,{ expiresIn: "7d" })
        
        return cb(null,{token:token,user:user,isNew:false})
        
      }
    }catch(err){
      console.error(err)
    }
  }
))

app.get(`/auth/google/register`, passport.authenticate('google', { session: false }),
    async(req,res)=>{
 
  if(req.user.isNew){
    const encodedemail = encodeURIComponent(req.user.email)
   return res.redirect(`${frontEndUrl}/gsignup?email=${encodedemail}`)
  }else{
   const user = encodeURIComponent(JSON.stringify(req.user.user))
    return res.redirect(`${frontEndUrl}/successlogin?token=${req.user.token}&user=${user}`)
  }
})

app.post('/auth/register/google',async(req,res)=>{
  const {name,email,school,role} = req.body
  try{
    const [rows] =await pool.query('INSERT INTO users (name,email,school,role) VALUES (?,?,?,?)',[name,email,school,role])
    const newuser =  {
      id: rows.insertId, 
      name,
      email,
      school,
      role
    };
    const token = jwt.sign({ id: newuser.id, role: newuser.role, email: newuser.email, name: newuser.name },JWT_SECRET,{ expiresIn: "7d" })
    const user = safeUser(newuser)
    return res.json({message:'Created user via Google!',token,user})
  }catch(err){
    res.json({message:"Error registering with google!"})
  }
})

// GET /me (optional, helpful)
app.get("/me", authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, name, email, school, role FROM users WHERE id = ?", [
      req.user.id,
    ]);
    if (rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch profile", error: err.message });
  }
});

// -------------------- POSTS --------------------
// GET /posts (students + lecturers)
app.get("/posts", authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `
      SELECT p.id, p.type, p.title, p.description, p.scheduled_at, p.created_by, p.created_at,
             u.name AS lecturer_name, u.school AS lecturer_school
      FROM posts p
      JOIN users u ON u.id = p.created_by
      ORDER BY p.scheduled_at ASC
      `
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch posts", error: err.message });
  }
});

// POST /posts (lecturer only)
app.post("/posts", authRequired, requireRole("lecturer"), async (req, res) => {
  try {
    const { type, title, description, scheduled_at } = req.body;

    if (!type || !title || !scheduled_at) {
      return res.status(400).json({ message: "Missing required fields (type, title, scheduled_at)" });
    }
    if (!["submission", "event", "meeting"].includes(type)) {
      return res.status(400).json({ message: "Invalid post type" });
    }

    const [result] = await pool.query(
      "INSERT INTO posts (type, title, description, scheduled_at, created_by) VALUES (?, ?, ?, ?, ?)",
      [type, title, description || "", scheduled_at, req.user.id]
    );

    res.status(201).json({
      message: "Post created",
      id: result.insertId,
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to create post", error: err.message });
  }
});

// PUT /posts/:id (lecturer only, only own posts)
app.put("/posts/:id", authRequired, requireRole("lecturer"), async (req, res) => {
  try {
    const postId = Number(req.params.id);
    const { type, title, description, scheduled_at } = req.body;

    if (!postId) return res.status(400).json({ message: "Invalid post id" });
    if (type && !["submission", "event", "meeting"].includes(type)) {
      return res.status(400).json({ message: "Invalid post type" });
    }

    // Ensure post belongs to lecturer
    const [check] = await pool.query("SELECT id FROM posts WHERE id = ? AND created_by = ?", [
      postId,
      req.user.id,
    ]);
    if (check.length === 0) return res.status(404).json({ message: "Post not found" });

    await pool.query(
      `
      UPDATE posts
      SET type = COALESCE(?, type),
          title = COALESCE(?, title),
          description = COALESCE(?, description),
          scheduled_at = COALESCE(?, scheduled_at)
      WHERE id = ? AND created_by = ?
      `,
      [type || null, title || null, description || null, scheduled_at || null, postId, req.user.id]
    );

    res.json({ message: "Post updated" });
  } catch (err) {
    res.status(500).json({ message: "Failed to update post", error: err.message });
  }
});

// DELETE /posts/:id (lecturer only, only own posts)
app.delete("/posts/:id", authRequired, requireRole("lecturer"), async (req, res) => {
  try {
    const postId = Number(req.params.id);
    if (!postId) return res.status(400).json({ message: "Invalid post id" });

    const [result] = await pool.query("DELETE FROM posts WHERE id = ? AND created_by = ?", [
      postId,
      req.user.id,
    ]);

    if (result.affectedRows === 0) return res.status(404).json({ message: "Post not found" });
    res.json({ message: "Post deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete post", error: err.message });
  }
});

// -------------------- REMINDERS --------------------
// POST /reminders (student + lecturer can set reminder)
app.post("/reminders", authRequired, async (req, res) => {
  try {
    const { post_id, remind_before_minutes } = req.body;

    const postId = Number(post_id);
    const minutes = Number(remind_before_minutes);

    if (!postId || !minutes) {
      return res.status(400).json({ message: "Missing post_id or remind_before_minutes" });
    }
    if (![60, 360, 720].includes(minutes)) {
      return res.status(400).json({ message: "Invalid remind_before_minutes (use 60, 360, 720)" });
    }

    // Get post time
    const [posts] = await pool.query("SELECT id, scheduled_at FROM posts WHERE id = ?", [postId]);
    if (posts.length === 0) return res.status(404).json({ message: "Post not found" });

    const scheduledAt = new Date(posts[0].scheduled_at);
    const reminderTime = new Date(scheduledAt.getTime() - minutes * 60 * 1000);

    // Insert (or update if duplicate)
    // because we used UNIQUE(user_id, post_id, remind_before_minutes)
    await pool.query(
      `
      INSERT INTO reminders (user_id, post_id, remind_before_minutes, reminder_time, status)
      VALUES (?, ?, ?, ?, 'pending')
      ON DUPLICATE KEY UPDATE reminder_time = VALUES(reminder_time), status = 'pending'
      `,
      [req.user.id, postId, minutes, reminderTime]
    );

    res.status(201).json({
      message: "Reminder set",
      reminder_time: reminderTime,
      status: "pending",
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to set reminder", error: err.message });
  }
});

// GET /reminders (user's reminders)
app.get("/reminders", authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `
      SELECT r.id, r.post_id, r.remind_before_minutes, r.reminder_time, r.status, r.created_at,
             p.type, p.title, p.scheduled_at
      FROM reminders r
      JOIN posts p ON p.id = r.post_id
      WHERE r.user_id = ?
      ORDER BY r.reminder_time ASC
      `,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch reminders", error: err.message });
  }
});

// -------------------- Start Server --------------------
app.listen(PORT, () => {
  console.log('═══════════════════════════════════════');
  console.log('Server Configuration:');
  console.log('─────────────────────────────────────');
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
  // console.log(`✓ Allowed origins:`, allowedOrigins.length > 0 ? allowedOrigins : 'localhost only');
  console.log('═══════════════════════════════════════');
});