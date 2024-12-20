const express = require("express");
const app = express();
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

app.use(express.json());



const corsOptions = {
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
const JWT_SECRET = "deepakbhagat";


const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "user_management",
  password: "root",
  port: 5432,
});



pool.connect((err) => {
  if (err) {
    console.error("Database connection error:", err.stack);
  } else {
    console.log("Database Connected");
  }
});


app.get("/", (req, res) => {
  res.send({ status: "Started" });
});

app.post("/register", async (req, res) => {
  const { name, email, mobile, password, userType } = req.body;

  try {
    const oldUser = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (oldUser.rows.length > 0) {
      return res.send({ data: "User already exists!!" });
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, email, mobile, password, userType) VALUES ($1, $2, $3, $4, $5)",
      [name, email, mobile, encryptedPassword, userType]
    );
    res.send({ status: "ok", data: "User Created" });
  } catch (error) {
    console.error(error);
    res.send({ status: "error", data: error });
  }
});

app.post("/login-user", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const oldUser = result.rows[0];

    if (!oldUser) {
      return res.send({ data: "User doesn't exist!!" });
    }

    if (await bcrypt.compare(password, oldUser.password)) {
      const token = jwt.sign({ email: oldUser.email }, JWT_SECRET);
      if (res.status(201)) {
        return res.send({
          status: "ok",
          data: token,
          userType: oldUser.usertype,
        });
      } else {
        return res.send({ error: "error" });
      }
    } else {
      res.send({ data: "Invalid credentials" });
    }
  } catch (error) {
    console.error(error);
    res.send({ status: "error", data: error });
  }
});

app.post("/userdata", async (req, res) => {
  const { token } = req.body;

  try {
    const user = jwt.verify(token, JWT_SECRET);
    const useremail = user.email;

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      useremail,
    ]);
    const data = result.rows[0];

    res.send({ status: "Ok", data: data });
  } catch (error) {
    console.error(error);
    res.send({ error: error });
  }
});

app.post("/update-user", async (req, res) => {
  const { name, email, mobile, image, gender, profession } = req.body;

  try {
    await pool.query(
      "UPDATE users SET name = $1, mobile = $2, image = $3, gender = $4, profession = $5 WHERE email = $6",
      [name, mobile, image, gender, profession, email]
    );
    res.send({ status: "Ok", data: "Updated" });
  } catch (error) {
    console.error(error);
    res.send({ error: error });
  }
});

app.get("/get-all-user", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users");
    res.send({ status: "Ok", data: result.rows });
  } catch (error) {
    console.error(error);
    res.send({ error: error });
  }
});

app.post("/delete-user", async (req, res) => {
  const { id } = req.body;

  try {
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
    res.send({ status: "Ok", data: "User Deleted" });
  } catch (error) {
    console.error(error);
    res.send({ error: error });
  }
});


app.listen(5001, () => {
  console.log("Node.js server started.");
});
