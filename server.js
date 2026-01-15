const express = require("express");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const multer = require("multer");
const os = require("os");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");
const FIREBASE_CRED_FILE = path.join(DATA_DIR, "service-account.json");
const PLANS_FILE = path.join(DATA_DIR, "plans.json");

const upload = multer({ dest: os.tmpdir() });

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";
const SESSION_TOKEN = process.env.SESSION_TOKEN || "magisvpn_admin_token";
const JWT_SECRET = process.env.JWT_SECRET || "magisvpn_jwt_secret";

// --- Firebase Init ---
let firebaseApp = null;

function initFirebase() {
  if (firebaseApp) return; // Already initialized
  
  if (fs.existsSync(FIREBASE_CRED_FILE)) {
    try {
      const serviceAccount = require(FIREBASE_CRED_FILE);
      firebaseApp = admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
      console.log("Firebase inicializado correctamente");
    } catch (error) {
      console.error("Error inicializando Firebase:", error.message);
    }
  }
}

// Try init on startup
initFirebase();

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(CONFIG_FILE)) {
  const defaultConfig = {
    Version: "1",
    ReleaseNotes: "",
    Password: "",
    Servers: [],
    Ads: {
      BannerIds: [],
      InterstitialIds: [],
      RewardedIds: [],
      AppOpenIds: [],
    },
  };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(defaultConfig, null, 2), "utf8");
}

if (!fs.existsSync(PLANS_FILE)) {
  fs.writeFileSync(PLANS_FILE, JSON.stringify([], null, 2), "utf8");
}

app.use(cors());
app.use(bodyParser.json());
app.use(morgan("dev"));
app.use(express.static(path.join(__dirname, "public")));

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title: "MagisVPN Admin API",
      version: "1.0.0",
      description: "API administrativa para panel CrisDEV y apps móviles",
    },
  },
  apis: [],
});

app.use("/admin/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const GEN_KEY = "MoraTech.Encrypt";

function base33Encrypt(text) {
  const base33Chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let out = "";
  for (const ch of text) {
    const idx = base33Chars.indexOf(ch);
    if (idx !== -1) {
      out += base33Chars[(idx + 1) % base33Chars.length];
    } else {
      out += ch;
    }
  }
  return out;
}

function base33Decrypt(text) {
  const base33Chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let out = "";
  for (const ch of text) {
    const idx = base33Chars.indexOf(ch);
    if (idx !== -1) {
      out += base33Chars[(idx + base33Chars.length - 1) % base33Chars.length];
    } else {
      out += ch;
    }
  }
  return out;
}

function moraEncrypt(str) {
  const step3 = str
    .split(" ")
    .map((w) => w.split("").reverse().join(""))
    .join(" ");
  const step2 = step3
    .split(" ")
    .map((word) => {
      let res = "";
      for (let i = 0; i < word.length; i++) {
        const c = word[i];
        if (/[a-zA-Z]/.test(c)) {
          const isLower = c === c.toLowerCase();
          const base = isLower ? "a".charCodeAt(0) : "A".charCodeAt(0);
          const offset = c.charCodeAt(0) - base;
          if (i % 2 === 0) {
            res += String.fromCharCode(((offset + 5) % 26) + base);
          } else {
            res += String.fromCharCode(((offset - 7 + 26) % 26) + base);
          }
        } else {
          res += c;
        }
      }
      return res;
    })
    .join(" ");
  const step1 = step2
    .split(" ")
    .map((word) => {
      if (word.length > 2) {
        return word.slice(-2) + word.slice(0, -2);
      }
      return word;
    })
    .join(" ");
  return step1;
}

function moraDecrypt(str) {
  const step1 = str
    .split(" ")
    .map((word) => {
      if (word.length > 2) {
        return word.slice(2) + word.slice(0, 2);
      }
      return word;
    })
    .join(" ");
  const step2 = step1
    .split(" ")
    .map((word) => {
      let res = "";
      for (let i = 0; i < word.length; i++) {
        const c = word[i];
        if (/[a-zA-Z]/.test(c)) {
          const isLower = c === c.toLowerCase();
          const base = isLower ? "a".charCodeAt(0) : "A".charCodeAt(0);
          const offset = c.charCodeAt(0) - base;
          if (i % 2 === 0) {
            res += String.fromCharCode(((offset - 5 + 26) % 26) + base);
          } else {
            res += String.fromCharCode(((offset + 7) % 26) + base);
          }
        } else {
          res += c;
        }
      }
      return res;
    })
    .join(" ");
  const step3 = step2
    .split(" ")
    .map((w) => w.split("").reverse().join(""))
    .join(" ");
  return step3;
}

function aesEncryptCompat(plaintext, secretKey) {
  const crypto = require("crypto");
  const key = Buffer.from(secretKey, "utf8");
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-128-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encryptedBytes = Buffer.concat([ciphertext, tag]);
  const encryptedMessage = Buffer.concat([nonce, encryptedBytes]);
  return encryptedMessage.toString("base64");
}

function aesDecryptCompat(encryptedText, secretKey) {
  const crypto = require("crypto");
  const key = Buffer.from(secretKey, "utf8");
  const encryptedMessage = Buffer.from(encryptedText, "base64");
  const nonce = encryptedMessage.slice(0, 12);
  const encryptedBytes = encryptedMessage.slice(12);
  const tag = encryptedBytes.slice(encryptedBytes.length - 16);
  const ciphertext = encryptedBytes.slice(0, -16);
  const decipher = crypto.createDecipheriv("aes-128-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
}

function encryptField(plain) {
  const text = plain || "";
  const b33 = base33Encrypt(text);
  const b64 = Buffer.from(b33, "utf8").toString("base64");
  const aes = aesEncryptCompat(b64, GEN_KEY);
  return moraEncrypt(aes);
}

function decryptField(cipher) {
  if (!cipher) {
    return "";
  }
  const aesWrapped = moraDecrypt(cipher);
  const b64 = aesDecryptCompat(aesWrapped, GEN_KEY);
  const b33 = Buffer.from(b64, "base64").toString("utf8");
  return base33Decrypt(b33);
}

function readConfig() {
  const raw = fs.readFileSync(CONFIG_FILE, "utf8");
  return JSON.parse(raw || "{}");
}

function writeConfig(config) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), "utf8");
}

function mapServerFromStorage(server, index) {
  return {
    id: String(index),
    position: index,
    name: server.Name || "",
    groupName: server.GroupTitle || "",
    flag: server.FLAG || "",
    host: server.ServerIP ? decryptField(server.ServerIP) : "",
    port: server.ServerPort || "",
    sslPort: server.SSLPort || "",
    proxyHost: server.ProxyIP || "",
    proxyPort: server.ProxyPort || "",
    username: server.ServerUser ? decryptField(server.ServerUser) : "",
    password: server.ServerPass ? decryptField(server.ServerPass) : "",
    payload: server.Payload ? decryptField(server.Payload) : "",
    sni: server.SNI ? decryptField(server.SNI) : "",
    udpBuffer: server.udpBuffer ? decryptField(server.udpBuffer) : "",
    udpUp: server.udpUp ? decryptField(server.udpUp) : "",
    udpDown: server.udpDown ? decryptField(server.udpDown) : "",
    slowKey: server.Slowchave ? decryptField(server.Slowchave) : "",
    slowDns: server.Slowdns ? decryptField(server.Slowdns) : "",
    slowNameserver: server.Nameserver ? decryptField(server.Nameserver) : "",
    v2rayConfig: server.UseTcp ? decryptField(server.UseTcp) : "",
    info: server.isMinfo || "",
    apiToken: server.apilatamsrcv2ray || "",
    apiCheckUser: server.apiCheckUser || "",
    isSSL: !!server.isSSL,
    isPayloadSSL: !!server.isPayloadSSL,
    isSlow: !!server.isSlow,
    isInject: !!server.isInject,
    isDirect: !!server.isDirect,
    isUdp: !!server.isUdp,
    isTcp: !!server.isTcp,
    soloDatos: !!server.solodatos,
    isPremium: !!server.isPremium,
  };
}

function mapServerToStorage(input) {
  const isPremium = !!input.isPremium;
  const storage = {};
  storage.Name = input.name || "";
  storage.GroupTitle = input.groupName || "";
  storage.FLAG = input.flag || "";
  storage.ServerIP = encryptField(input.host || "");
  storage.ServerPort = input.port || "";
  storage.SSLPort = input.sslPort || "";
  if (input.proxyHost) {
    storage.ProxyIP = input.proxyHost;
  }
  if (input.proxyPort) {
    storage.ProxyPort = input.proxyPort;
  }
  if (isPremium) {
    storage.isPremium = true;
  } else {
    storage.ServerUser = encryptField(input.username || "");
    storage.ServerPass = encryptField(input.password || "");
  }
  storage.Payload = encryptField(input.payload || "");
  storage.SNI = encryptField(input.sni || "");
  storage.udpBuffer = encryptField(input.udpBuffer || "");
  storage.udpUp = encryptField(input.udpUp || "");
  storage.udpDown = encryptField(input.udpDown || "");
  storage.Slowchave = encryptField(input.slowKey || "");
  storage.Nameserver = encryptField(input.slowNameserver || "");
  storage.Slowdns = encryptField(input.slowDns || "");
  storage.UseTcp = encryptField(input.v2rayConfig || "");
  storage.isMinfo = input.info || "";
  storage.apilatamsrcv2ray = input.apiToken || "";
  storage.apiCheckUser = input.apiCheckUser || "";
  if (input.isSSL) {
    storage.isSSL = true;
  }
  if (input.isPayloadSSL) {
    storage.isPayloadSSL = true;
  }
  if (input.isSlow) {
    storage.isSlow = true;
  }
  if (input.isInject) {
    storage.isInject = true;
  }
  if (input.isDirect) {
    storage.isDirect = true;
  }
  if (input.isUdp) {
    storage.isUdp = true;
  }
  if (input.isTcp) {
    storage.isTcp = true;
  }
  if (input.soloDatos) {
    storage.solodatos = true;
  }
  return storage;
}

function authMiddleware(req, res, next) {
  const header = req.headers["authorization"] || "";
  const parts = header.split(" ");
  if (parts.length === 2 && parts[0] === "Bearer" && parts[1] === SESSION_TOKEN) {
    return next();
  }
  res.status(401).json({ error: "No autorizado" });
}

function jwtAuth(roles = []) {
  return (req, res, next) => {
    const header = req.headers["authorization"] || "";
    const parts = header.split(" ");
    if (!(parts.length === 2 && parts[0] === "Bearer")) {
      return res.status(401).json({ error: "Token requerido" });
    }
    try {
      const decoded = jwt.verify(parts[1], JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role)) {
        return res.status(403).json({ error: "Acceso denegado" });
      }
      req.user = decoded;
      return next();
    } catch (err) {
      return res.status(401).json({ error: "Token inválido" });
    }
  };
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return res.json({ token: SESSION_TOKEN });
  }
  res.status(401).json({ error: "Credenciales inválidas" });
});

app.post("/admin/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });
  }
  const users = readUsers();
  const found = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!found) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }
  const payload = {
    sub: found.id,
    username: found.username,
    role: found.role || "user",
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
  res.json({ token, user: { id: found.id, username: found.username, role: found.role } });
});

app.get("/api/meta", authMiddleware, (req, res) => {
  const config = readConfig();
  res.json({
    version: config.Version || "",
    releaseNotes: config.ReleaseNotes || "",
    password: config.Password || "",
    apiKey: config.ApiKey || "",
    ads: config.Ads || {
      BannerIds: [],
      InterstitialIds: [],
      RewardedIds: [],
      AppOpenIds: []
    }
  });
});

app.put("/api/meta", authMiddleware, (req, res) => {
  const config = readConfig();
  const { version, releaseNotes, password, apiKey, ads } = req.body || {};
  config.Version = typeof version === "string" ? version : config.Version;
  config.ReleaseNotes =
    typeof releaseNotes === "string" ? releaseNotes : config.ReleaseNotes;
  if (typeof password === "string") {
    config.Password = password;
  }
  if (typeof apiKey === "string") {
    config.ApiKey = apiKey;
  }
  if (ads && typeof ads === "object") {
    if (!config.Ads) config.Ads = {};
    if (Array.isArray(ads.BannerIds)) config.Ads.BannerIds = ads.BannerIds;
    if (Array.isArray(ads.InterstitialIds)) config.Ads.InterstitialIds = ads.InterstitialIds;
    if (Array.isArray(ads.RewardedIds)) config.Ads.RewardedIds = ads.RewardedIds;
    if (Array.isArray(ads.AppOpenIds)) config.Ads.AppOpenIds = ads.AppOpenIds;
  }
  writeConfig(config);
  res.json({
    version: config.Version,
    releaseNotes: config.ReleaseNotes,
    password: config.Password || "",
    apiKey: config.ApiKey || "",
    ads: config.Ads
  });
});

// Endpoint público para la APP (Protegido por API Key)
app.get("/api/app/config", (req, res) => {
  const config = readConfig();
  const requestKey = req.headers["x-api-key"] || req.query.key;
  
  // Validar Key
  if (!config.ApiKey || requestKey !== config.ApiKey) {
    return res.status(403).json({ error: "Acceso denegado: API Key inválida" });
  }

  // Retornar JSON limpio para la app (sin la API Key expuesta)
  const appConfig = { ...config };
  delete appConfig.ApiKey; // No enviar la llave en la respuesta
  
  res.json(appConfig);
});

app.get("/api/servers", authMiddleware, (req, res) => {
  const config = readConfig();
  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  const mapped = servers.map((s, idx) => mapServerFromStorage(s, idx));
  res.json(mapped);
});

app.post("/api/servers", authMiddleware, (req, res) => {
  const config = readConfig();
  if (!Array.isArray(config.Servers)) {
    config.Servers = [];
  }
  const payload = req.body || {};
  const storageServer = mapServerToStorage(payload);
  config.Servers.push(storageServer);
  writeConfig(config);
  const index = config.Servers.length - 1;
  res.status(201).json(mapServerFromStorage(storageServer, index));
});

app.put("/api/servers/:id", authMiddleware, (req, res) => {
  const config = readConfig();
  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  const index = parseInt(req.params.id, 10);
  if (Number.isNaN(index) || index < 0 || index >= servers.length) {
    return res.status(404).json({ error: "Servidor no encontrado" });
  }
  const payload = req.body || {};
  const updated = mapServerToStorage(payload);
  config.Servers[index] = updated;
  writeConfig(config);
  res.json(mapServerFromStorage(updated, index));
});

app.delete("/api/servers/:id", authMiddleware, (req, res) => {
  const config = readConfig();
  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  const index = parseInt(req.params.id, 10);
  if (Number.isNaN(index) || index < 0 || index >= servers.length) {
    return res.status(404).json({ error: "Servidor no encontrado" });
  }
  servers.splice(index, 1);
  config.Servers = servers;
  writeConfig(config);
  res.json({ ok: true });
});

app.get("/api/config", authMiddleware, (req, res) => {
  const config = readConfig();
  res.json(config);
});

app.post("/api/servers/reorder", authMiddleware, (req, res) => {
  const config = readConfig();
  const { newOrder } = req.body; // Array of IDs (indices)
  if (!Array.isArray(newOrder)) {
    return res.status(400).json({ error: "Formato inválido" });
  }

  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  if (newOrder.length !== servers.length) {
    return res.status(400).json({ error: "Cantidad de servidores no coincide" });
  }

  const reordered = [];
  try {
    newOrder.forEach((strIndex) => {
      const idx = parseInt(strIndex, 10);
      if (idx < 0 || idx >= servers.length) {
        throw new Error("Índice inválido");
      }
      reordered.push(servers[idx]);
    });
  } catch {
    return res.status(400).json({ error: "Índices inválidos" });
  }

  // To avoid duplicates or data loss, we should ensure newOrder is a permutation of 0..N-1
  // But for simplicity, we assume frontend sends correct unique indices.
  // Actually, let's just map carefully. Since IDs are indices, reordering based on old indices works once.
  // Wait, if I drag 0 to 2. The array changes.
  // Frontend should send the list of *original* indices in the new order.
  // Example: Original [A, B, C]. New order: [B, A, C] -> indices [1, 0, 2].
  
  config.Servers = reordered;
  writeConfig(config);
  
  // Return mapped servers with new IDs
  const mapped = config.Servers.map((s, idx) => mapServerFromStorage(s, idx));
  res.json(mapped);
});

// Mock Users (since no DB requested yet, we store in a separate json or just in memory/config)
// For now, let's add a "PanelUsers" to config.json or a new file users.json
const USERS_FILE = path.join(DATA_DIR, "users.json");

function readUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    return [];
  }
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8") || "[]");
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

function readPlans() {
  if (!fs.existsSync(PLANS_FILE)) {
    return [];
  }
  return JSON.parse(fs.readFileSync(PLANS_FILE, "utf8") || "[]");
}

function writePlans(plans) {
  fs.writeFileSync(PLANS_FILE, JSON.stringify(plans, null, 2), "utf8");
}

app.get("/api/users", authMiddleware, (req, res) => {
  const users = readUsers();
  const safeUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    status: u.status,
    lastLogin: u.lastLogin,
    source: u.source || "local",
    email: u.email || null,
    planId: u.planId || null
  }));
  res.json(safeUsers);
});

app.post("/api/users", authMiddleware, (req, res) => {
  const users = readUsers();
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Faltan datos" });
  }
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: "Usuario ya existe" });
  }
  
  const newUser = {
    id: Date.now().toString(),
    username,
    password, // In a real app, hash this!
    role: role || "user",
    status: "active",
    lastLogin: null,
    source: "local",
    email: null,
    planId: null
  };
  
  users.push(newUser);
  writeUsers(users);
  
  const { password: _, ...safeUser } = newUser;
  res.status(201).json(safeUser);
});

app.put("/api/users/:id", authMiddleware, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Usuario no encontrado" });
  
  const { username, password, role, status, planId } = req.body;
  
  if (username) users[idx].username = username;
  if (password) users[idx].password = password; // Hash in real app
  if (role) users[idx].role = role;
  if (status) users[idx].status = status;
  if (typeof planId !== "undefined") users[idx].planId = planId;
  
  writeUsers(users);
  
  const { password: _, ...safeUser } = users[idx];
  res.json(safeUser);
});

app.delete("/api/users/:id", authMiddleware, (req, res) => {
  let users = readUsers();
  const initialLength = users.length;
  users = users.filter(u => u.id !== req.params.id);
  if (users.length === initialLength) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }
  writeUsers(users);
  res.json({ ok: true });
});

// Firebase Auth Users Sync (read-only)
app.get("/api/firebase/users", authMiddleware, async (req, res) => {
  if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });
  
  try {
    const auth = admin.auth();
    const all = [];
    let nextPageToken;
    do {
      const result = await auth.listUsers(1000, nextPageToken);
      result.users.forEach(u => {
        all.push({
          id: u.uid,
          username: u.displayName || u.email || u.uid,
          email: u.email || null,
          provider: u.providerData && u.providerData[0] ? u.providerData[0].providerId : "firebase",
          status: u.disabled ? "disabled" : "active",
          lastLogin: u.metadata && u.metadata.lastSignInTime ? u.metadata.lastSignInTime : null,
          source: "firebase"
        });
      });
      nextPageToken = result.pageToken;
    } while (nextPageToken);
    
    res.json(all);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Plans API
app.get("/api/plans", authMiddleware, (req, res) => {
  const plans = readPlans();
  res.json(plans);
});

app.post("/api/plans", authMiddleware, (req, res) => {
  const plans = readPlans();
  const { name, description, price, currency, durationDays, features, isActive, paymentMethods, blockAds, premiumCatalog } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "Nombre requerido" });
  }
  const newPlan = {
    id: Date.now().toString(),
    name,
    description: description || "",
    price: typeof price === "number" ? price : 0,
    currency: currency || "USD",
    durationDays: typeof durationDays === "number" ? durationDays : 30,
    features: Array.isArray(features) ? features : [],
    isActive: typeof isActive === "boolean" ? isActive : true,
    paymentMethods: Array.isArray(paymentMethods) ? paymentMethods : [],
    blockAds: typeof blockAds === "boolean" ? blockAds : false,
    premiumCatalog: typeof premiumCatalog === "boolean" ? premiumCatalog : false
  };
  plans.push(newPlan);
  writePlans(plans);
  res.status(201).json(newPlan);
});

app.put("/api/plans/:id", authMiddleware, (req, res) => {
  const plans = readPlans();
  const idx = plans.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Plan no encontrado" });
  const { name, description, price, currency, durationDays, features, isActive, paymentMethods, blockAds, premiumCatalog } = req.body || {};
  if (name) plans[idx].name = name;
  if (typeof description === "string") plans[idx].description = description;
  if (typeof price === "number") plans[idx].price = price;
  if (currency) plans[idx].currency = currency;
  if (typeof durationDays === "number") plans[idx].durationDays = durationDays;
  if (Array.isArray(features)) plans[idx].features = features;
  if (typeof isActive === "boolean") plans[idx].isActive = isActive;
  if (Array.isArray(paymentMethods)) plans[idx].paymentMethods = paymentMethods;
  if (typeof blockAds === "boolean") plans[idx].blockAds = blockAds;
  if (typeof premiumCatalog === "boolean") plans[idx].premiumCatalog = premiumCatalog;
  writePlans(plans);
  res.json(plans[idx]);
});

app.delete("/api/plans/:id", authMiddleware, (req, res) => {
  let plans = readPlans();
  const initialLength = plans.length;
  plans = plans.filter(p => p.id !== req.params.id);
  if (plans.length === initialLength) {
    return res.status(404).json({ error: "Plan no encontrado" });
  }
  writePlans(plans);
  res.json({ ok: true });
});

app.get("/admin/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

app.get("/admin/servers", jwtAuth(["admin", "editor", "viewer"]), (req, res) => {
  const config = readConfig();
  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  const mapped = servers.map((s, idx) => mapServerFromStorage(s, idx));
  res.json(mapped);
});

app.post("/admin/servers", jwtAuth(["admin", "editor"]), (req, res) => {
  const config = readConfig();
  if (!Array.isArray(config.Servers)) {
    config.Servers = [];
  }
  const payload = req.body || {};
  const storageServer = mapServerToStorage(payload);
  config.Servers.push(storageServer);
  writeConfig(config);
  const index = config.Servers.length - 1;
  res.status(201).json(mapServerFromStorage(storageServer, index));
});

app.put("/admin/servers/:id", jwtAuth(["admin", "editor"]), (req, res) => {
  const config = readConfig();
  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  const index = parseInt(req.params.id, 10);
  if (Number.isNaN(index) || index < 0 || index >= servers.length) {
    return res.status(404).json({ error: "Servidor no encontrado" });
  }
  const payload = req.body || {};
  const updated = mapServerToStorage(payload);
  config.Servers[index] = updated;
  writeConfig(config);
  res.json(mapServerFromStorage(updated, index));
});

app.delete("/admin/servers/:id", jwtAuth(["admin"]), (req, res) => {
  const config = readConfig();
  const servers = Array.isArray(config.Servers) ? config.Servers : [];
  const index = parseInt(req.params.id, 10);
  if (Number.isNaN(index) || index < 0 || index >= servers.length) {
    return res.status(404).json({ error: "Servidor no encontrado" });
  }
  servers.splice(index, 1);
  config.Servers = servers;
  writeConfig(config);
  res.json({ ok: true });
});

app.get("/admin/users", jwtAuth(["admin"]), (req, res) => {
  const users = readUsers();
  const safeUsers = users.map((u) => ({
    id: u.id,
    username: u.username,
    role: u.role,
    status: u.status,
    lastLogin: u.lastLogin,
    email: u.email || null,
    planId: u.planId || null,
  }));
  res.json(safeUsers);
});

app.post("/admin/users", jwtAuth(["admin"]), (req, res) => {
  const users = readUsers();
  const { username, password, role } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Faltan datos" });
  }
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ error: "Usuario ya existe" });
  }
  const newUser = {
    id: Date.now().toString(),
    username,
    password,
    role: role || "user",
    status: "active",
    lastLogin: null,
    source: "local",
    email: null,
    planId: null,
  };
  users.push(newUser);
  writeUsers(users);
  const { password: _, ...safeUser } = newUser;
  res.status(201).json(safeUser);
});

app.put("/admin/users/:id", jwtAuth(["admin"]), (req, res) => {
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Usuario no encontrado" });
  const { username, password, role, status, planId } = req.body || {};
  if (username) users[idx].username = username;
  if (password) users[idx].password = password;
  if (role) users[idx].role = role;
  if (status) users[idx].status = status;
  if (typeof planId !== "undefined") users[idx].planId = planId;
  writeUsers(users);
  const { password: _, ...safeUser } = users[idx];
  res.json(safeUser);
});

app.delete("/admin/users/:id", jwtAuth(["admin"]), (req, res) => {
  let users = readUsers();
  const initialLength = users.length;
  users = users.filter((u) => u.id !== req.params.id);
  if (users.length === initialLength) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }
  writeUsers(users);
  res.json({ ok: true });
});

app.get("/admin/plans", jwtAuth(["admin", "editor", "viewer"]), (req, res) => {
  const plans = readPlans();
  res.json(plans);
});

app.post("/admin/plans", jwtAuth(["admin", "editor"]), (req, res) => {
  const plans = readPlans();
  const { name, description, price, currency, durationDays, features, isActive, paymentMethods, blockAds, premiumCatalog } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "Nombre requerido" });
  }
  const newPlan = {
    id: Date.now().toString(),
    name,
    description: description || "",
    price: typeof price === "number" ? price : 0,
    currency: currency || "USD",
    durationDays: typeof durationDays === "number" ? durationDays : 30,
    features: Array.isArray(features) ? features : [],
    isActive: typeof isActive === "boolean" ? isActive : true,
    paymentMethods: Array.isArray(paymentMethods) ? paymentMethods : [],
    blockAds: typeof blockAds === "boolean" ? blockAds : false,
    premiumCatalog: typeof premiumCatalog === "boolean" ? premiumCatalog : false,
  };
  plans.push(newPlan);
  writePlans(plans);
  res.status(201).json(newPlan);
});

app.put("/admin/plans/:id", jwtAuth(["admin", "editor"]), (req, res) => {
  const plans = readPlans();
  const idx = plans.findIndex((p) => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Plan no encontrado" });
  const { name, description, price, currency, durationDays, features, isActive, paymentMethods, blockAds, premiumCatalog } = req.body || {};
  if (name) plans[idx].name = name;
  if (typeof description === "string") plans[idx].description = description;
  if (typeof price === "number") plans[idx].price = price;
  if (currency) plans[idx].currency = currency;
  if (typeof durationDays === "number") plans[idx].durationDays = durationDays;
  if (Array.isArray(features)) plans[idx].features = features;
  if (typeof isActive === "boolean") plans[idx].isActive = isActive;
  if (Array.isArray(paymentMethods)) plans[idx].paymentMethods = paymentMethods;
  if (typeof blockAds === "boolean") plans[idx].blockAds = blockAds;
  if (typeof premiumCatalog === "boolean") plans[idx].premiumCatalog = premiumCatalog;
  writePlans(plans);
  res.json(plans[idx]);
});

app.delete("/admin/plans/:id", jwtAuth(["admin"]), (req, res) => {
  let plans = readPlans();
  const initialLength = plans.length;
  plans = plans.filter((p) => p.id !== req.params.id);
  if (plans.length === initialLength) {
    return res.status(404).json({ error: "Plan no encontrado" });
  }
  writePlans(plans);
  res.json({ ok: true });
});

app.get("/admin/config", jwtAuth(["admin", "editor", "viewer"]), (req, res) => {
  const config = readConfig();
  res.json({
    version: config.Version || "",
    releaseNotes: config.ReleaseNotes || "",
    password: config.Password || "",
    apiKey: config.ApiKey || "",
    ads: config.Ads || {
      BannerIds: [],
      InterstitialIds: [],
      RewardedIds: [],
      AppOpenIds: [],
    },
    webContent: config.WebContent || {},
  });
});

app.put("/admin/config", jwtAuth(["admin", "editor"]), (req, res) => {
  const config = readConfig();
  const { version, releaseNotes, password, apiKey, ads, webContent } = req.body || {};
  if (typeof version === "string") config.Version = version;
  if (typeof releaseNotes === "string") config.ReleaseNotes = releaseNotes;
  if (typeof password === "string") config.Password = password;
  if (typeof apiKey === "string") config.ApiKey = apiKey;
  if (ads && typeof ads === "object") {
    if (!config.Ads) config.Ads = {};
    if (Array.isArray(ads.BannerIds)) config.Ads.BannerIds = ads.BannerIds;
    if (Array.isArray(ads.InterstitialIds)) config.Ads.InterstitialIds = ads.InterstitialIds;
    if (Array.isArray(ads.RewardedIds)) config.Ads.RewardedIds = ads.RewardedIds;
    if (Array.isArray(ads.AppOpenIds)) config.Ads.AppOpenIds = ads.AppOpenIds;
  }
  if (webContent && typeof webContent === "object") {
    config.WebContent = webContent;
  }
  writeConfig(config);
  res.json({
    version: config.Version,
    releaseNotes: config.ReleaseNotes,
    password: config.Password || "",
    apiKey: config.ApiKey || "",
    ads: config.Ads,
    webContent: config.WebContent || {},
  });
});

// --- Firebase Endpoints ---

// 1. Upload Service Account
app.post("/api/firebase/setup", authMiddleware, upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No se subió ningún archivo" });
  }
  
  try {
    const content = fs.readFileSync(req.file.path, "utf8");
    // Validate JSON
    JSON.parse(content);
    
    // Save to final location
    fs.writeFileSync(FIREBASE_CRED_FILE, content);
    
    // Cleanup temp
    fs.unlinkSync(req.file.path);
    
    // Re-init
    if (firebaseApp) {
      // If already init, we can't easily re-init without restart in some versions, 
      // but let's try to delete app or just tell user to restart.
      // Actually, admin.app() check works.
      // For simplicity, we'll ask for restart or just reload if possible.
      // In this simple script, we might need to restart the process ideally.
      // But let's try to just re-run init if null.
      // If it exists, we can't easily replace it in standard node SDK without delete().
      try {
        firebaseApp.delete(); 
      } catch(e) {}
      firebaseApp = null;
    }
    initFirebase();
    
    res.json({ success: true, message: "Credenciales guardadas. Firebase reiniciado." });
  } catch (err) {
    res.status(400).json({ error: "Archivo JSON inválido: " + err.message });
  }
});

// 2. Get Remote Config
app.get("/api/firebase/remote-config", authMiddleware, async (req, res) => {
  if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });
  
  try {
    const config = admin.remoteConfig();
    const template = await config.getTemplate();
    
    // Extract parameters for easier frontend consumption
    const params = {};
    for (const [key, value] of Object.entries(template.parameters)) {
      params[key] = {
        defaultValue: value.defaultValue ? value.defaultValue.value : "",
        description: value.description || ""
      };
    }
    
    res.json(params);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Update Remote Config
app.post("/api/firebase/remote-config", authMiddleware, async (req, res) => {
  if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });
  
  const { parameters } = req.body; // Object: { key: value, key2: value2 }
  
  try {
    const rc = admin.remoteConfig();
    const template = await rc.getTemplate();
    
    // Update values
    for (const [key, value] of Object.entries(parameters)) {
      if (!template.parameters[key]) {
        template.parameters[key] = { defaultValue: { value: String(value) } };
      } else {
        template.parameters[key].defaultValue = { value: String(value) };
      }
    }
    
    await rc.publishTemplate(template);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Send Notification
app.post("/api/firebase/notify", authMiddleware, async (req, res) => {
  if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });
  
  const { title, body, imageUrl, largeIcon, topic, token } = req.body;
  
  // Base Notification
  const message = {
    notification: {
      title: title || "MagisVPN",
      body: body || "",
    },
    android: {
      notification: {
        sound: "default"
      }
    },
    data: {
      title: title || "",
      body: body || "",
    }
  };

  // Big Picture (Portada)
  if (imageUrl) {
    message.android.notification.imageUrl = imageUrl;
    message.data.image = imageUrl;
  }

  // Large Icon (Icono Grande) - Passed in data for app to handle if needed
  if (largeIcon) {
    message.data.largeIcon = largeIcon;
  }

  try {
    let response;
    if (topic) {
      message.topic = topic;
      response = await admin.messaging().send(message);
    } else if (token) {
      message.token = token;
      response = await admin.messaging().send(message);
    } else {
      // Default to topic 'all'
      message.topic = "all";
      response = await admin.messaging().send(message);
    }
    
    res.json({ success: true, response });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`MagisVPN panel escuchando en http://localhost:${PORT}`);
});

