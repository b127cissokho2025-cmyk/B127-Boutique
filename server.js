const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "b127-secret-a-changer";

const db = new Database("b127.db");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'customer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    price REAL NOT NULL,
    category TEXT DEFAULT 'Autres',
    image TEXT DEFAULT '',
    stock INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    total REAL NOT NULL,
    payment_method TEXT DEFAULT 'COD',
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "Connexion requise" });
  }

  try {
    const token = header.replace("Bearer ", "");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session invalide" });
  }
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "B127 Boutique",
    message: "B127 fonctionne correctement"
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Nom, email et mot de passe obligatoires"
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = db.prepare(`
      INSERT INTO users (name, email, password)
      VALUES (?, ?, ?)
    `).run(name, email.toLowerCase(), hash);

    const user = {
      id: result.lastInsertRowid,
      name,
      email: email.toLowerCase(),
      role: "customer"
    };

    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

    res.json({ user, token });
  } catch (error) {
    res.status(400).json({
      error: "Cet email est peut-être déjà utilisé"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare(`
    SELECT * FROM users WHERE email = ?
  `).get((email || "").toLowerCase());

  if (!user || !(await bcrypt.compare(password || "", user.password))) {
    return res.status(401).json({
      error: "Email ou mot de passe incorrect"
    });
  }

  const safeUser = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };

  const token = jwt.sign(safeUser, JWT_SECRET, {
    expiresIn: "7d"
  });

  res.json({
    user: safeUser,
    token
  });
});

app.get("/api/products", (req, res) => {
  const products = db.prepare(`
    SELECT * FROM products
    ORDER BY id DESC
  `).all();

  res.json(products);
});

app.post("/api/products", auth, (req, res) => {
  const {
    name,
    description,
    price,
    category,
    image,
    stock
  } = req.body;

  if (!name || price === undefined) {
    return res.status(400).json({
      error: "Nom et prix obligatoires"
    });
  }

  const result = db.prepare(`
    INSERT INTO products
    (seller_id, name, description, price, category, image, stock)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    req.user.id,
    name,
    description || "",
    Number(price),
    category || "Autres",
    image || "",
    Number(stock || 0)
  );

  res.json({
    success: true,
    id: result.lastInsertRowid
  });
});

app.post("/api/orders", auth, (req, res) => {
  const {
    total,
    payment_method
  } = req.body;

  if (!total) {
    return res.status(400).json({
      error: "Montant de commande obligatoire"
    });
  }

  const result = db.prepare(`
    INSERT INTO orders
    (user_id, total, payment_method)
    VALUES (?, ?, ?)
  `).run(
    req.user.id,
    Number(total),
    payment_method || "COD"
  );

  res.json({
    success: true,
    order_id: result.lastInsertRowid,
    message: "Commande enregistrée"
  });
});

app.get("/api/orders", auth, (req, res) => {
  const orders = db.prepare(`
    SELECT *
    FROM orders
    WHERE user_id = ?
    ORDER BY id DESC
  `).all(req.user.id);

  res.json(orders);
});

app.get("/api/admin/summary", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Accès administrateur refusé"
    });
  }

  const users = db.prepare(
    "SELECT COUNT(*) AS count FROM users"
  ).get().count;

  const products = db.prepare(
    "SELECT COUNT(*) AS count FROM products"
  ).get().count;

  const orders = db.prepare(
    "SELECT COUNT(*) AS count FROM orders"
  ).get().count;

  res.json({
    users,
    products,
    orders
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`B127 Boutique démarrée sur le port ${PORT}`);
});
