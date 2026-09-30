const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-b127-secret-in-production";
const db = new Database("b127.db");

db.pragma("foreign_keys = ON");

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  phone TEXT DEFAULT '',
  role TEXT NOT NULL DEFAULT 'customer',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sellers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  category TEXT DEFAULT 'Autres',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seller_id INTEGER,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price REAL NOT NULL CHECK(price >= 0),
  category TEXT DEFAULT 'Autres',
  image TEXT DEFAULT '',
  stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
  active INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_ref TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  city TEXT DEFAULT '',
  neighborhood TEXT DEFAULT '',
  address TEXT NOT NULL,
  total REAL NOT NULL CHECK(total >= 0),
  payment_method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  product_name TEXT NOT NULL,
  unit_price REAL NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity > 0),
  subtotal REAL NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS favorites (
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, product_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
);
`);

function addColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();

  if (!columns.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

addColumn("users", "phone", "TEXT DEFAULT ''");
addColumn("products", "active", "INTEGER NOT NULL DEFAULT 1");

const cleanEmail = (v) => String(v || "").trim().toLowerCase();

const money = (v) => Math.round(Number(v) * 100) / 100;

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone || "",
    role: user.role
  };
}

function issueToken(user) {
  return jwt.sign(
    publicUser(user),
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      error: "Connexion requise"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Session invalide"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Accès administrateur refusé"
    });
  }

  next();
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
    const name = String(req.body.name || "").trim();
    const email = cleanEmail(req.body.email);
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Nom, email et mot de passe obligatoires"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 6 caractères"
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = db.prepare(
      "INSERT INTO users (name,email,password,phone) VALUES (?,?,?,?)"
    ).run(name, email, hash, phone);

    const user = db.prepare(
      "SELECT * FROM users WHERE id=?"
    ).get(result.lastInsertRowid);

    res.status(201).json({
      user: publicUser(user),
      token: issueToken(user)
    });

  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: "Cet email est peut-être déjà utilisé"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || "");

  const user = db.prepare(
    "SELECT * FROM users WHERE email=?"
  ).get(email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({
      error: "Email ou mot de passe incorrect"
    });
  }

  res.json({
    user: publicUser(user),
    token: issueToken(user)
  });
});

app.get("/api/me", auth, (req, res) => {
  const user = db.prepare(
    "SELECT * FROM users WHERE id=?"
  ).get(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "Utilisateur introuvable"
    });
  }

  res.json({
    user: publicUser(user)
  });
});

app.get("/api/categories", (req, res) => {
  res.json(
    db.prepare(`
      SELECT category, COUNT(*) AS count
      FROM products
      WHERE active=1
      GROUP BY category
      ORDER BY category ASC
    `).all()
  );
});

app.get("/api/products", (req, res) => {
  const q = String(req.query.q || "").trim();
  const category = String(req.query.category || "").trim();

  let sql = `
    SELECT p.*, s.name AS seller_name
    FROM products p
    LEFT JOIN sellers s ON s.user_id=p.seller_id
    WHERE p.active=1
  `;

  const args = [];

  if (q) {
    sql += `
      AND (
        p.name LIKE ?
        OR p.description LIKE ?
        OR p.category LIKE ?
      )
    `;

    const x = `%${q}%`;
    args.push(x, x, x);
  }

  if (category) {
    sql += " AND p.category=?";
    args.push(category);
  }

  sql += " ORDER BY p.id DESC";

  res.json(
    db.prepare(sql).all(...args)
  );
});

app.post("/api/products", auth, (req, res) => {
  if (!["seller", "admin"].includes(req.user.role)) {
    return res.status(403).json({
      error: "Créez d'abord votre boutique vendeur"
    });
  }

  const name = String(req.body.name || "").trim();
  const description = String(req.body.description || "");
  const price = Number(req.body.price);
  const stock = Number(req.body.stock || 0);
  const category = String(
    req.body.category || "Autres"
  ).trim();

  const image = String(
    req.body.image || req.body.icon || ""
  );

  if (
    !name ||
    !Number.isFinite(price) ||
    price < 0 ||
    !Number.isInteger(stock) ||
    stock < 0
  ) {
    return res.status(400).json({
      error: "Nom, prix et stock valides obligatoires"
    });
  }

  const result = db.prepare(`
    INSERT INTO products
    (seller_id,name,description,price,category,image,stock)
    VALUES (?,?,?,?,?,?,?)
  `).run(
    req.user.id,
    name,
    description,
    money(price),
    category,
    image,
    stock
  );

  res.status(201).json({
    success: true,
    id: result.lastInsertRowid
  });
});
app.patch("/api/products/:id", auth, (req, res) => {
  const id = Number(req.params.id);

  const product = db.prepare(
    "SELECT * FROM products WHERE id=?"
  ).get(id);

  if (!product) {
    return res.status(404).json({
      error: "Produit introuvable"
    });
  }

  if (
    req.user.role !== "admin" &&
    product.seller_id !== req.user.id
  ) {
    return res.status(403).json({
      error: "Accès refusé"
    });
  }

  const name = String(
    req.body.name ?? product.name
  ).trim();

  const description = String(
    req.body.description ?? product.description
  );

  const price = Number(
    req.body.price ?? product.price
  );

  const category = String(
    req.body.category ?? product.category
  ).trim();

  const image = String(
    req.body.image ?? product.image
  );

  const stock = Number(
    req.body.stock ?? product.stock
  );

  const active =
    req.body.active === undefined
      ? product.active
      : (req.body.active ? 1 : 0);

  if (
    !name ||
    !Number.isFinite(price) ||
    price < 0 ||
    !Number.isInteger(stock) ||
    stock < 0
  ) {
    return res.status(400).json({
      error: "Données produit invalides"
    });
  }

  db.prepare(`
    UPDATE products
    SET name=?,
        description=?,
        price=?,
        category=?,
        image=?,
        stock=?,
        active=?
    WHERE id=?
  `).run(
    name,
    description,
    money(price),
    category,
    image,
    stock,
    active,
    id
  );

  res.json({
    success: true
  });
});

app.delete("/api/products/:id", auth, (req, res) => {
  const id = Number(req.params.id);

  const product = db.prepare(
    "SELECT * FROM products WHERE id=?"
  ).get(id);

  if (!product) {
    return res.status(404).json({
      error: "Produit introuvable"
    });
  }

  if (
    req.user.role !== "admin" &&
    product.seller_id !== req.user.id
  ) {
    return res.status(403).json({
      error: "Accès refusé"
    });
  }

  db.prepare(
    "UPDATE products SET active=0 WHERE id=?"
  ).run(id);

  res.json({
    success: true
  });
});

app.post("/api/orders", auth, (req, res) => {
  const customerName = String(
    req.body.customer_name || ""
  ).trim();

  const phone = String(
    req.body.phone || ""
  ).trim();

  const city = String(
    req.body.city || ""
  ).trim();

  const neighborhood = String(
    req.body.neighborhood || ""
  ).trim();

  const address = String(
    req.body.address || ""
  ).trim();

  const payment = String(
    req.body.payment_method ||
    req.body.payment ||
    "COD"
  );

  const items = Array.isArray(req.body.items)
    ? req.body.items
    : [];

  if (
    !customerName ||
    !phone ||
    !address ||
    !items.length
  ) {
    return res.status(400).json({
      error: "Informations client et panier obligatoires"
    });
  }

  if (
    !["Wave", "Orange Money", "COD"].includes(payment)
  ) {
    return res.status(400).json({
      error: "Mode de paiement invalide"
    });
  }

  try {
    const result = db.transaction(() => {
      let total = 0;
      const normalized = [];

      for (const item of items) {
        const productId = Number(item.id);

        const quantity = Math.floor(
          Number(
            item.quantity ??
            item.qty ??
            1
          )
        );

        if (
          !Number.isInteger(productId) ||
          !Number.isInteger(quantity) ||
          quantity < 1
        ) {
          throw new Error(
            "Article invalide"
          );
        }

        const product = db.prepare(`
          SELECT *
          FROM products
          WHERE id=? AND active=1
        `).get(productId);

        if (!product) {
          throw new Error(
            "Produit introuvable"
          );
        }

        if (product.stock < quantity) {
          throw new Error(
            `Stock insuffisant pour : ${product.name}`
          );
        }

        const subtotal = money(
          product.price * quantity
        );

        total += subtotal;

        normalized.push({
          product,
          quantity,
          subtotal
        });
      }

      total = money(total);

      const orderRef =
        `B127-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;

      const order = db.prepare(`
        INSERT INTO orders (
          order_ref,
          user_id,
          customer_name,
          phone,
          city,
          neighborhood,
          address,
          total,
          payment_method
        )
        VALUES (?,?,?,?,?,?,?,?,?)
      `).run(
        orderRef,
        req.user.id,
        customerName,
        phone,
        city,
        neighborhood,
        address,
        total,
        payment
      );

      const addItem = db.prepare(`
        INSERT INTO order_items (
          order_id,
          product_id,
          product_name,
          unit_price,
          quantity,
          subtotal
        )
        VALUES (?,?,?,?,?,?)
      `);

      const reduceStock = db.prepare(
        "UPDATE products SET stock=stock-? WHERE id=?"
      );

      for (const item of normalized) {
        addItem.run(
          order.lastInsertRowid,
          item.product.id,
          item.product.name,
          item.product.price,
          item.quantity,
          item.subtotal
        );

        reduceStock.run(
          item.quantity,
          item.product.id
        );
      }

      return {
        id: order.lastInsertRowid,
        order_ref: orderRef,
        total
      };
    })();

    res.status(201).json({
      success: true,
      order: result,
      message: "Commande enregistrée"
    });

  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: error.message ||
        "Commande impossible"
    });
  }
});

app.get("/api/orders", auth, (req, res) => {
  const orders = db.prepare(`
    SELECT *
    FROM orders
    WHERE user_id=?
    ORDER BY id DESC
  `).all(req.user.id);

  const items = db.prepare(`
    SELECT *
    FROM order_items
    WHERE order_id IN (
      SELECT id
      FROM orders
      WHERE user_id=?
    )
    ORDER BY id
  `).all(req.user.id);

  res.json(
    orders.map(order => ({
      ...order,
      items: items.filter(
        item => item.order_id === order.id
      )
    }))
  );
});

app.get("/api/orders/:id", auth, (req, res) => {
  const order = db.prepare(`
    SELECT *
    FROM orders
    WHERE id=? AND user_id=?
  `).get(
    Number(req.params.id),
    req.user.id
  );

  if (!order) {
    return res.status(404).json({
      error: "Commande introuvable"
    });
  }

  order.items = db.prepare(`
    SELECT *
    FROM order_items
    WHERE order_id=?
    ORDER BY id
  `).all(order.id);

  res.json(order);
});
app.get("/api/favorites", auth, (req, res) => {
  const favorites = db.prepare(`
    SELECT p.*
    FROM favorites f
    JOIN products p ON p.id=f.product_id
    WHERE f.user_id=? AND p.active=1
    ORDER BY f.created_at DESC
  `).all(req.user.id);

  res.json(favorites);
});

app.post("/api/favorites/:productId", auth, (req, res) => {
  const productId = Number(req.params.productId);

  const product = db.prepare(
    "SELECT id FROM products WHERE id=? AND active=1"
  ).get(productId);

  if (!product) {
    return res.status(404).json({
      error: "Produit introuvable"
    });
  }

  const existing = db.prepare(`
    SELECT *
    FROM favorites
    WHERE user_id=? AND product_id=?
  `).get(
    req.user.id,
    productId
  );

  if (existing) {
    db.prepare(`
      DELETE FROM favorites
      WHERE user_id=? AND product_id=?
    `).run(
      req.user.id,
      productId
    );

    return res.json({
      favorite: false
    });
  }

  db.prepare(`
    INSERT INTO favorites (user_id, product_id)
    VALUES (?,?)
  `).run(
    req.user.id,
    productId
  );

  res.json({
    favorite: true
  });
});

app.post("/api/sellers", auth, (req, res) => {
  if (req.user.role === "admin") {
    return res.status(400).json({
      error: "Un administrateur ne peut pas créer une boutique vendeur"
    });
  }

  const existing = db.prepare(`
    SELECT *
    FROM sellers
    WHERE user_id=?
  `).get(req.user.id);

  if (existing) {
    return res.json({
      seller: existing
    });
  }

  const name = String(
    req.body.name || req.user.name
  ).trim();

  const phone = String(
    req.body.phone || ""
  ).trim();

  const category = String(
    req.body.category || "Autres"
  ).trim();

  if (!name) {
    return res.status(400).json({
      error: "Nom de boutique obligatoire"
    });
  }

  const createSeller = db.transaction(() => {
    const result = db.prepare(`
      INSERT INTO sellers (
        user_id,
        name,
        phone,
        category
      )
      VALUES (?,?,?,?)
    `).run(
      req.user.id,
      name,
      phone,
      category
    );

    db.prepare(`
      UPDATE users
      SET role='seller'
      WHERE id=?
    `).run(req.user.id);

    return db.prepare(
      "SELECT * FROM sellers WHERE id=?"
    ).get(result.lastInsertRowid);
  });

  const seller = createSeller();

  res.status(201).json({
    seller
  });
});

app.get("/api/seller", auth, (req, res) => {
  const seller = db.prepare(`
    SELECT *
    FROM sellers
    WHERE user_id=?
  `).get(req.user.id);

  if (!seller) {
    return res.status(404).json({
      error: "Aucune boutique vendeur"
    });
  }

  const products = db.prepare(`
    SELECT *
    FROM products
    WHERE seller_id=?
    ORDER BY id DESC
  `).all(req.user.id);

  res.json({
    seller,
    products
  });
});

app.get("/api/admin/summary", auth, adminOnly, (req, res) => {
  const users = db.prepare(
    "SELECT COUNT(*) AS count FROM users"
  ).get().count;

  const products = db.prepare(
    "SELECT COUNT(*) AS count FROM products WHERE active=1"
  ).get().count;

  const orders = db.prepare(
    "SELECT COUNT(*) AS count FROM orders"
  ).get().count;

  const revenue = db.prepare(`
    SELECT COALESCE(SUM(total),0) AS total
    FROM orders
    WHERE status != 'cancelled'
  `).get().total;

  const pending = db.prepare(`
    SELECT COUNT(*) AS count
    FROM orders
    WHERE status='pending'
  `).get().count;

  const sellers = db.prepare(`
    SELECT COUNT(*) AS count
    FROM sellers
  `).get().count;

  res.json({
    users,
    products,
    orders,
    revenue: money(revenue),
    pending,
    sellers
  });
});

app.get("/api/admin/orders", auth, adminOnly, (req, res) => {
  const orders = db.prepare(`
    SELECT
      o.*,
      u.email AS customer_email
    FROM orders o
    LEFT JOIN users u ON u.id=o.user_id
    ORDER BY o.id DESC
  `).all();

  const items = db.prepare(`
    SELECT *
    FROM order_items
    ORDER BY id
  `).all();

  res.json(
    orders.map(order => ({
      ...order,
      items: items.filter(
        item => item.order_id === order.id
      )
    }))
  );
});

app.patch(
  "/api/admin/orders/:id/status",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);
    const status = String(
      req.body.status || ""
    );

    const allowed = [
      "pending",
      "confirmed",
      "shipped",
      "delivered",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "Statut invalide"
      });
    }

    const order = db.prepare(
      "SELECT * FROM orders WHERE id=?"
    ).get(id);

    if (!order) {
      return res.status(404).json({
        error: "Commande introuvable"
      });
    }

    db.prepare(`
      UPDATE orders
      SET status=?
      WHERE id=?
    `).run(
      status,
      id
    );

    res.json({
      success: true,
      status
    });
  }
);

app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT
      id,
      name,
      email,
      phone,
      role,
      created_at
    FROM users
    ORDER BY id DESC
  `).all();

  res.json(users);
});

app.get("/api/admin/products", auth, adminOnly, (req, res) => {
  const products = db.prepare(`
    SELECT
      p.*,
      u.name AS seller_name
    FROM products p
    LEFT JOIN users u ON u.id=p.seller_id
    ORDER BY p.id DESC
  `).all();

  res.json(products);
});

app.get("/api/sellers", (req, res) => {
  const sellers = db.prepare(`
    SELECT
      s.*,
      u.email,
      u.role
    FROM sellers s
    JOIN users u ON u.id=s.user_id
    ORDER BY s.id DESC
  `).all();

  res.json(sellers);
});

app.get("/api/stats", (req, res) => {
  const products = db.prepare(`
    SELECT COUNT(*) AS count
    FROM products
    WHERE active=1
  `).get().count;

  const sellers = db.prepare(`
    SELECT COUNT(*) AS count
    FROM sellers
  `).get().count;

  const orders = db.prepare(`
    SELECT COUNT(*) AS count
    FROM orders
  `).get().count;

  res.json({
    products,
    sellers,
    orders
  });
});

app.use((req, res, next) => {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api/")
  ) {
    return res.sendFile(
      path.join(__dirname, "public", "index.html")
    );
  }

  next();
});

app.use((err, req, res, next) => {
  console.error("B127 server error:", err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Erreur interne du serveur"
  });
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`B127 Boutique démarrée sur le port ${PORT}`);
});
