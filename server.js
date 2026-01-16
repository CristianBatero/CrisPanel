const express = require("express");
require("dotenv").config();
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
const crypto = require("crypto");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";
const SESSION_TOKEN = process.env.SESSION_TOKEN || "crispanel_admin_token";
const JWT_SECRET = process.env.JWT_SECRET || "crispanel_jwt_secret";
const GEN_KEY = process.env.GEN_KEY || "MoraTech.Encrypt";

// --- Storage Adapters ---

class StorageAdapter {
  async read(filename, defaultValue) { throw new Error("Not implemented"); }
  async write(filename, data) { throw new Error("Not implemented"); }
}

class FileStorage extends StorageAdapter {
  constructor() {
    super();
    this.baseDir = DATA_DIR;
    // Check if we are in a read-only environment (like Lambda/Netlify) and not using GitHub Storage
    try {
        if (!fs.existsSync(this.baseDir)) {
            fs.mkdirSync(this.baseDir, { recursive: true });
        }
        // Test write access
        const testFile = path.join(this.baseDir, ".test");
        fs.writeFileSync(testFile, "test");
        fs.unlinkSync(testFile);
    } catch (e) {
        console.warn("Warning: Could not write to local data directory. Falling back to /tmp/crispanel_data.", e.message);
        this.baseDir = path.join(os.tmpdir(), "crispanel_data");
        try {
          if (!fs.existsSync(this.baseDir)) fs.mkdirSync(this.baseDir, { recursive: true });
        } catch (err) {
          console.error("Critical: Could not create temp data dir", err);
        }
    }
  }

  async read(filename, defaultValue) {
    const filePath = path.join(this.baseDir, filename);
    if (!fs.existsSync(filePath)) {
      if (defaultValue !== undefined) {
        // Try to write default value, but handle error if read-only
        try {
            await this.write(filename, defaultValue);
            return { data: defaultValue, sha: null };
        } catch (e) {
            console.warn(`Could not write default value for ${filename} in FileStorage`, e.message);
            return { data: defaultValue, sha: null }; // Return default even if we couldn't save it
        }
      }
      return { data: null, sha: null };
    }
    const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return { data: json, sha: null };
  }

  async write(filename, data, sha = null) {
    const filePath = path.join(this.baseDir, filename);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
  }
}

class GitHubStorage extends StorageAdapter {
  constructor() {
    super();
    this.token = process.env.GITHUB_TOKEN;
    this.owner = process.env.GITHUB_OWNER || "CristianBatero"; 
    this.repo = process.env.GITHUB_REPO || "CrisPanel";
    this.branch = process.env.GITHUB_BRANCH || "main";
    this.api = axios.create({
      baseURL: `https://api.github.com/repos/${this.owner}/${this.repo}/contents/data`,
      headers: {
        Authorization: `Bearer ${this.token}`,
        Accept: "application/vnd.github.v3+json",
      },
    });
  }

  async read(filename, defaultValue) {
    try {
      // Add timestamp to prevent caching
      const res = await this.api.get(`/${filename}?ref=${this.branch}&t=${Date.now()}`);
      const content = Buffer.from(res.data.content, "base64").toString("utf8");
      return { data: JSON.parse(content), sha: res.data.sha };
    } catch (e) {
      if (e.response && e.response.status === 404) {
        if (defaultValue !== undefined) {
          // Create the file
          await this.write(filename, defaultValue);
          return { data: defaultValue, sha: null }; // Next write will get SHA or handle conflict
        }
        return { data: null, sha: null };
      }
      console.error("GitHub Read Error:", e.message);
      throw e;
    }
  }

  async write(filename, data, sha = null) {
    let currentSha = sha;
    if (!currentSha) {
      try {
        const res = await this.api.get(`/${filename}?ref=${this.branch}`);
        currentSha = res.data.sha;
      } catch (e) {}
    }

    const content = Buffer.from(JSON.stringify(data, null, 2)).toString("base64");
    const body = {
      message: `Update ${filename} via Panel`,
      content: content,
      branch: this.branch,
    };
    if (currentSha) body.sha = currentSha;

    await this.api.put(`/${filename}`, body);
  }
}

const storage = process.env.GITHUB_TOKEN ? new GitHubStorage() : new FileStorage();

// --- Firebase Init ---
let firebaseApp = null;

async function ensureFirebase() {
  if (firebaseApp) return firebaseApp;

  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const creds = JSON.parse(
        Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, "base64").toString("utf8")
      );
      firebaseApp = admin.initializeApp({ credential: admin.credential.cert(creds) });
      console.log("Firebase initialized from Env");
      return firebaseApp;
    } catch (e) {
      console.error("Error init Firebase from Env:", e.message);
    }
  }

  try {
    const { data: creds } = await storage.read("service-account.json", null);
    if (creds) {
      firebaseApp = admin.initializeApp({ credential: admin.credential.cert(creds) });
      console.log("Firebase initialized from Storage");
    } else {
      console.warn("Firebase service-account.json not found in storage");
    }
  } catch (e) {
    console.error("Error init Firebase from Storage:", e.message);
  }

  return firebaseApp;
}

// --- Middleware & Config ---
app.use(cors());
app.use(bodyParser.json());
app.use(morgan("dev"));
app.use(express.static(path.join(__dirname, "public")));

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: { title: "CrisPanel v1.0 Admin API", version: "1.0.0" },
  },
  apis: [],
});
app.use("/admin/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// --- Encryption Helpers (Unchanged) ---
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  const parts = stored.split("$");
  if (parts.length === 3 && parts[0] === "scrypt") {
    const [, salt, hash] = parts;
    const hashBuffer = Buffer.from(hash, "hex");
    const derived = crypto.scryptSync(password, salt, hashBuffer.length);
    return crypto.timingSafeEqual(derived, hashBuffer);
  }
  return password === stored;
}

function base33Encrypt(text) {
  const base33Chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let out = "";
  for (const ch of text) {
    const idx = base33Chars.indexOf(ch);
    if (idx !== -1) out += base33Chars[(idx + 1) % base33Chars.length];
    else out += ch;
  }
  return out;
}

function base33Decrypt(text) {
  const base33Chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let out = "";
  for (const ch of text) {
    const idx = base33Chars.indexOf(ch);
    if (idx !== -1) out += base33Chars[(idx + base33Chars.length - 1) % base33Chars.length];
    else out += ch;
  }
  return out;
}

function moraEncrypt(str) {
  const step3 = str.split(" ").map((w) => w.split("").reverse().join("")).join(" ");
  const step2 = step3.split(" ").map((word) => {
    let res = "";
    for (let i = 0; i < word.length; i++) {
      const c = word[i];
      if (/[a-zA-Z]/.test(c)) {
        const isLower = c === c.toLowerCase();
        const base = isLower ? "a".charCodeAt(0) : "A".charCodeAt(0);
        const offset = c.charCodeAt(0) - base;
        if (i % 2 === 0) res += String.fromCharCode(((offset + 5) % 26) + base);
        else res += String.fromCharCode(((offset - 7 + 26) % 26) + base);
      } else res += c;
    }
    return res;
  }).join(" ");
  const step1 = step2.split(" ").map((word) => {
    if (word.length > 2) return word.slice(-2) + word.slice(0, -2);
    return word;
  }).join(" ");
  return step1;
}

function moraDecrypt(str) {
  const step1 = str.split(" ").map((word) => {
    if (word.length > 2) return word.slice(2) + word.slice(0, 2);
    return word;
  }).join(" ");
  const step2 = step1.split(" ").map((word) => {
    let res = "";
    for (let i = 0; i < word.length; i++) {
      const c = word[i];
      if (/[a-zA-Z]/.test(c)) {
        const isLower = c === c.toLowerCase();
        const base = isLower ? "a".charCodeAt(0) : "A".charCodeAt(0);
        const offset = c.charCodeAt(0) - base;
        if (i % 2 === 0) res += String.fromCharCode(((offset - 5 + 26) % 26) + base);
        else res += String.fromCharCode(((offset + 7) % 26) + base);
      } else res += c;
    }
    return res;
  }).join(" ");
  return step2.split(" ").map((w) => w.split("").reverse().join("")).join(" ");
}

function aesEncryptCompat(plaintext, secretKey) {
  const crypto = require("crypto");
  const key = Buffer.from(secretKey, "utf8");
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-128-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ciphertext, tag]).toString("base64");
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
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function encryptField(plain) {
  const text = plain || "";
  const b33 = base33Encrypt(text);
  const b64 = Buffer.from(b33, "utf8").toString("base64");
  const aes = aesEncryptCompat(b64, GEN_KEY);
  return moraEncrypt(aes);
}

function decryptField(cipher) {
  if (!cipher) return "";
  try {
    const aesWrapped = moraDecrypt(cipher);
    const b64 = aesDecryptCompat(aesWrapped, GEN_KEY);
    const b33 = Buffer.from(b64, "base64").toString("utf8");
    return base33Decrypt(b33);
  } catch(e) { return ""; }
}

// --- Mappers ---
function mapServerFromStorage(server, index) {
    // Same implementation as before
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
    if (input.proxyHost) storage.ProxyIP = input.proxyHost;
    if (input.proxyPort) storage.ProxyPort = input.proxyPort;
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
    if (input.isSSL) storage.isSSL = true;
    if (input.isPayloadSSL) storage.isPayloadSSL = true;
    if (input.isSlow) storage.isSlow = true;
    if (input.isInject) storage.isInject = true;
    if (input.isDirect) storage.isDirect = true;
    if (input.isUdp) storage.isUdp = true;
    if (input.isTcp) storage.isTcp = true;
    if (input.soloDatos) storage.solodatos = true;
    return storage;
}

function mapDeviceForAdmin(device) {
  const adSeconds = device.adSeconds || 0;
  const totalHours = Math.round((adSeconds / 3600) * 100) / 100;
  return {
    id: device.id,
    deviceId: device.deviceId,
    model: device.model || "",
    appVersion: device.appVersion || "",
    adSeconds,
    totalHours,
    createdAt: device.createdAt || null,
    lastSeen: device.lastSeen || null,
    lastAdAt: device.lastAdAt || null,
  };
}

function mapDeviceForApp(device) {
  const adSeconds = device.adSeconds || 0;
  const totalHours = Math.round((adSeconds / 3600) * 100) / 100;
  return {
    id: device.id,
    deviceId: device.deviceId,
    adSeconds,
    totalHours,
    lastAdAt: device.lastAdAt || null,
  };
}

// --- Auth Middleware ---
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

async function requireApiKey(req, res) {
  const { data: config } = await storage.read("config.json", {});
  const requestKey = req.headers["x-api-key"] || req.query.key;
  if (!config.ApiKey || requestKey !== config.ApiKey) {
    res.status(403).json({ error: "Acceso denegado: API Key inválida" });
    return null;
  }
  
  // Ensure Ads structure exists
  if (!config.Ads) config.Ads = {};
  if (!Array.isArray(config.Ads.BannerIds)) config.Ads.BannerIds = [];
  if (!Array.isArray(config.Ads.InterstitialIds)) config.Ads.InterstitialIds = [];
  if (!Array.isArray(config.Ads.RewardedIds)) config.Ads.RewardedIds = [];
  if (!Array.isArray(config.Ads.AppOpenIds)) config.Ads.AppOpenIds = [];
  
  return config;
}

// --- Endpoints ---

// Upload Service Account
const upload = multer({ storage: multer.memoryStorage() });

app.post("/api/firebase/setup", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const content = JSON.parse(req.file.buffer.toString("utf8"));

    const { sha } = await storage.read("service-account.json", null);
    await storage.write("service-account.json", content, sha);

    firebaseApp = null;
    await ensureFirebase();

    res.json({ message: "Firebase configurado correctamente." });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Login Simple
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return res.json({ token: SESSION_TOKEN });
  }
  res.status(401).json({ error: "Credenciales inválidas" });
});

// Admin Auth (Users)
app.post("/admin/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Faltan datos" });
  
  try {
    const result = await storage.read("users.json", []);
    const users = result.data || [];
    
    const found = users.find(u => u.username === username && verifyPassword(password, u.password));
    if (!found) return res.status(401).json({ error: "Credenciales inválidas" });
    
    const payload = { sub: found.id, username: found.username, role: found.role || "user" };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, user: { id: found.id, username: found.username, role: found.role } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Meta
app.get("/api/meta", authMiddleware, async (req, res) => {
  try {
    const { data: config } = await storage.read("config.json", {});
    res.json({
      version: config.Version || "",
      releaseNotes: config.ReleaseNotes || "",
      password: config.Password || "",
      apiKey: config.ApiKey || "",
      ads: config.Ads || { BannerIds: [], InterstitialIds: [], RewardedIds: [], AppOpenIds: [] }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/meta", authMiddleware, async (req, res) => {
  try {
    const { data: config, sha } = await storage.read("config.json", {});
    const { version, releaseNotes, password, apiKey, ads } = req.body || {};
    
    if (version !== undefined) config.Version = version;
    if (releaseNotes !== undefined) config.ReleaseNotes = releaseNotes;
    if (password !== undefined) config.Password = password;
    if (apiKey !== undefined) config.ApiKey = apiKey;
    if (ads) config.Ads = { ...config.Ads, ...ads };
    
    await storage.write("config.json", config, sha);
    res.json(config);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// App Config (Public w/ Key)
app.get("/api/app/config", async (req, res) => {
  try {
    const config = await requireApiKey(req, res);
    if (!config) return;
    const appConfig = { ...config };
    delete appConfig.ApiKey;
    appConfig.ads = config.Ads || { BannerIds: [], InterstitialIds: [], RewardedIds: [], AppOpenIds: [] };
    res.json(appConfig);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/app/device/register", async (req, res) => {
  try {
    const config = await requireApiKey(req, res);
    if (!config) return;
    const body = req.body || {};
    const deviceId = body.deviceId;
    if (!deviceId) return res.status(400).json({ error: "deviceId requerido" });
    const result = await storage.read("devices.json", []);
    const devices = Array.isArray(result.data) ? result.data : [];
    const now = Date.now();
    let device = devices.find(d => d.deviceId === deviceId);
    if (!device) {
      device = {
        id: Date.now().toString(),
        deviceId,
        model: body.model || "",
        appVersion: body.appVersion || "",
        adSeconds: 0,
        createdAt: now,
        lastSeen: now,
        lastAdAt: null,
      };
      devices.push(device);
    } else {
      if (body.model) device.model = body.model;
      if (body.appVersion) device.appVersion = body.appVersion;
      device.lastSeen = now;
    }
    await storage.write("devices.json", devices, result.sha);
    res.json(mapDeviceForApp(device));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/app/device/reward", async (req, res) => {
  try {
    const config = await requireApiKey(req, res);
    if (!config) return;
    const body = req.body || {};
    const deviceId = body.deviceId;
    if (!deviceId) return res.status(400).json({ error: "deviceId requerido" });
    const adsCountRaw = body.adsCount != null ? body.adsCount : 1;
    const count = Number(adsCountRaw) || 1;
    const hoursPerAd = 2;
    const addedSeconds = count * hoursPerAd * 3600;
    const result = await storage.read("devices.json", []);
    const devices = Array.isArray(result.data) ? result.data : [];
    const now = Date.now();
    let device = devices.find(d => d.deviceId === deviceId);
    if (!device) {
      device = {
        id: Date.now().toString(),
        deviceId,
        model: body.model || "",
        appVersion: body.appVersion || "",
        adSeconds: 0,
        createdAt: now,
        lastSeen: now,
        lastAdAt: null,
      };
      devices.push(device);
    }
    const current = device.adSeconds || 0;
    device.adSeconds = current + addedSeconds;
    device.lastSeen = now;
    device.lastAdAt = now;
    await storage.write("devices.json", devices, result.sha);
    const summary = mapDeviceForApp(device);
    res.json({
      ...summary,
      addedSeconds,
      addedHours: addedSeconds / 3600,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Servers
app.get("/api/servers", authMiddleware, async (req, res) => {
  try {
    const { data: config } = await storage.read("config.json", {});
    const servers = Array.isArray(config.Servers) ? config.Servers : [];
    res.json(servers.map((s, idx) => mapServerFromStorage(s, idx)));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/servers", authMiddleware, async (req, res) => {
  try {
    const { data: config, sha } = await storage.read("config.json", {});
    if (!Array.isArray(config.Servers)) config.Servers = [];
    
    const payload = req.body || {};
    const storageServer = mapServerToStorage(payload);
    config.Servers.push(storageServer);
    
    await storage.write("config.json", config, sha);
    const index = config.Servers.length - 1;
    res.status(201).json(mapServerFromStorage(storageServer, index));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/servers/:id", authMiddleware, async (req, res) => {
  try {
    const { data: config, sha } = await storage.read("config.json", {});
    const servers = Array.isArray(config.Servers) ? config.Servers : [];
    const index = parseInt(req.params.id, 10);
    
    if (Number.isNaN(index) || index < 0 || index >= servers.length) {
      return res.status(404).json({ error: "Servidor no encontrado" });
    }
    
    const updated = mapServerToStorage(req.body);
    config.Servers[index] = updated;
    await storage.write("config.json", config, sha);
    res.json(mapServerFromStorage(updated, index));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/servers/:id", authMiddleware, async (req, res) => {
  try {
    const { data: config, sha } = await storage.read("config.json", {});
    const servers = Array.isArray(config.Servers) ? config.Servers : [];
    const index = parseInt(req.params.id, 10);
    
    if (Number.isNaN(index) || index < 0 || index >= servers.length) {
      return res.status(404).json({ error: "Servidor no encontrado" });
    }
    
    servers.splice(index, 1);
    config.Servers = servers;
    await storage.write("config.json", config, sha);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Users
app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    const { data: users } = await storage.read("users.json", []);
    res.json(users.map(u => ({ ...u, password: undefined })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/devices", authMiddleware, async (req, res) => {
  try {
    const result = await storage.read("devices.json", []);
    const devices = Array.isArray(result.data) ? result.data : [];
    res.json(devices.map(mapDeviceForAdmin));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/users", authMiddleware, async (req, res) => {
  try {
    const { data: users, sha } = await storage.read("users.json", []);
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Faltan datos" });
    
    if (users.find(u => u.username === username)) return res.status(400).json({ error: "Existe" });
    
    const newUser = {
      id: Date.now().toString(),
      username,
      password: hashPassword(password),
      role: role || "user",
      status: "active",
      lastLogin: null,
      source: "local"
    };
    users.push(newUser);
    await storage.write("users.json", users, sha);
    
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/users/:id", authMiddleware, async (req, res) => {
  try {
    const { data: users, sha } = await storage.read("users.json", []);
    const idx = users.findIndex(u => u.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "No encontrado" });
    
    const { username, password, role, status, planId } = req.body;
    if (username) users[idx].username = username;
    if (password) users[idx].password = hashPassword(password);
    if (role) users[idx].role = role;
    if (status) users[idx].status = status;
    if (planId !== undefined) users[idx].planId = planId;
    
    await storage.write("users.json", users, sha);
    const { password: _, ...safe } = users[idx];
    res.json(safe);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/users/:id", authMiddleware, async (req, res) => {
  try {
    const { data: users, sha } = await storage.read("users.json", []);
    const initialLen = users.length;
    const newUsers = users.filter(u => u.id !== req.params.id);
    if (newUsers.length === initialLen) return res.status(404).json({ error: "No encontrado" });
    
    await storage.write("users.json", newUsers, sha);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Plans
app.get("/api/plans", authMiddleware, async (req, res) => {
  try {
    const { data: plans } = await storage.read("plans.json", []);
    res.json(plans);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/plans", authMiddleware, async (req, res) => {
  try {
    const { data: plans, sha } = await storage.read("plans.json", []);
    const newPlan = { ...req.body, id: Date.now().toString() };
    if (!newPlan.name) return res.status(400).json({ error: "Nombre requerido" });
    plans.push(newPlan);
    await storage.write("plans.json", plans, sha);
    res.status(201).json(newPlan);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/plans/:id", authMiddleware, async (req, res) => {
  try {
    const { data: plans, sha } = await storage.read("plans.json", []);
    const idx = plans.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "No encontrado" });
    
    plans[idx] = { ...plans[idx], ...req.body };
    await storage.write("plans.json", plans, sha);
    res.json(plans[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/plans/:id", authMiddleware, async (req, res) => {
  try {
    const { data: plans, sha } = await storage.read("plans.json", []);
    const newPlans = plans.filter(p => p.id !== req.params.id);
    if (newPlans.length === plans.length) return res.status(404).json({ error: "No encontrado" });
    
    await storage.write("plans.json", newPlans, sha);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/firebase/remote-config", authMiddleware, async (req, res) => {
  try {
    await ensureFirebase();
    if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });

    const config = admin.remoteConfig();
    const template = await config.getTemplate();
    const params = {};
    for (const [key, value] of Object.entries(template.parameters)) {
      params[key] = {
        defaultValue: value.defaultValue ? value.defaultValue.value : "",
        description: value.description || ""
      };
    }
    res.json(params);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/firebase/remote-config", authMiddleware, async (req, res) => {
  try {
    await ensureFirebase();
    if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });

    const { parameters } = req.body;
    const rc = admin.remoteConfig();
    const template = await rc.getTemplate();
    for (const [key, value] of Object.entries(parameters)) {
      if (!template.parameters[key]) template.parameters[key] = { defaultValue: { value: String(value) } };
      else template.parameters[key].defaultValue = { value: String(value) };
    }
    await rc.publishTemplate(template);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/firebase/notify", authMiddleware, async (req, res) => {
  try {
    await ensureFirebase();
    if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });

    const { title, body, imageUrl, largeIcon, topic, token } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: "Título y cuerpo requeridos" });
    if (!topic && !token) return res.status(400).json({ error: "Debe especificar topic o token" });

    const notification = { title, body };
    if (imageUrl) notification.image = imageUrl;

    const android = { notification: {}, priority: "high" };
    if (largeIcon) android.notification.icon = largeIcon;

    const message = { notification, android };
    if (topic) message.topic = topic;
    else message.token = token;

    const id = await admin.messaging().send(message);
    res.json({ success: true, id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/firebase/users", authMiddleware, async (req, res) => {
  try {
    await ensureFirebase();
    if (!firebaseApp) return res.status(503).json({ error: "Firebase no configurado" });

    const listUsersResult = await admin.auth().listUsers(1000);
    const users = listUsersResult.users.map(u => ({
      id: u.uid,
      email: u.email,
      username: u.displayName || u.email,
      source: "firebase",
      status: u.disabled ? "inactive" : "active",
      lastLogin: u.metadata.lastSignInTime,
      role: "user"
    }));
    res.json(users);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/health", (req, res) => {
  res.json({ 
    status: "ok", 
    timestamp: Date.now(),
    storage: process.env.GITHUB_TOKEN ? "github" : "local",
    firebase: !!firebaseApp
  });
});

// Only listen if not in Netlify (Lambda)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`CrisPanel v1.0 escuchando en http://localhost:${PORT}`);
  });
}

module.exports = app;
