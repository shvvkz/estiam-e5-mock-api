import express from "express";
import cors from "cors";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import dotenv from "dotenv";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "your-super-secret-refresh-key-change-in-production";
const UPLOADS_DIR = path.join(__dirname, "uploads");
const DB_PATH = path.join(__dirname, "data", "trips.json");

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function loadTrips() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    console.warn("No trips.json found, starting empty DB.");
    return [];
  }
}
function saveTrips(trips) {
  fs.writeFileSync(DB_PATH, JSON.stringify(trips, null, 2), "utf8");
}
let trips = loadTrips();

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    const safeExt = ext ? ext : "";
    cb(null, `${Date.now()}-${uuidv4()}${safeExt}`);
  }
});
const upload = multer({ storage });

// Middleware pour vérifier le token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
};

app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// Route d'inscription
app.post("/auth/register", (req, res) => {
  const { email, password, name } = req.body || {};
  
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, password and name are required' });
  }

  const userId = uuidv4();
  const user = {
    id: userId,
    name: name,
    email: email,
    roles: ["student"]
  };

  // Générer access token (expire dans 1 heure)
  const accessToken = jwt.sign(
    { userId, email, roles: user.roles },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Générer refresh token (expire dans 7 jours)
  const refreshToken = jwt.sign(
    { userId, email },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return res.json({
    accessToken,
    refreshToken,
    expiresIn: 3600, // 1 heure en secondes
    user
  });
});

// Route de connexion
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // En production, vérifier le mot de passe dans la base de données
  // Pour le mock, on accepte n'importe quel email/password
  const userId = uuidv4();
  const user = {
    id: userId,
    name: email?.split("@")[0] || "Utilisateur",
    email: email || "user@example.com",
    roles: ["student"]
  };

  // Générer access token (expire dans 1 heure)
  const accessToken = jwt.sign(
    { userId, email: user.email, roles: user.roles },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Générer refresh token (expire dans 7 jours)
  const refreshToken = jwt.sign(
    { userId, email: user.email },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return res.json({
    accessToken,
    refreshToken,
    expiresIn: 3600, // 1 heure en secondes
    user
  });
});

// Route de refresh token
app.post("/auth/refresh", (req, res) => {
  const { refreshToken } = req.body || {};
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    // Générer un nouveau access token
    const accessToken = jwt.sign(
      { userId: decoded.userId, email: decoded.email, roles: ["student"] },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({
      accessToken,
      expiresIn: 3600
    });
  });
});

// Route de déconnexion
app.post("/auth/logout", authenticateToken, (req, res) => {
  // En production, invalider le refresh token dans la base de données
  // Pour le mock, on retourne juste un succès
  return res.json({ message: 'Logged out successfully' });
});

app.get("/trips", authenticateToken, (req, res) => {
  return res.json(trips);
});

app.post("/trips", authenticateToken, (req, res) => {
  const payload = req.body || {};
  const id = uuidv4();
  const newTrip = {
    id,
    title: payload.title || "Sans titre",
    destination: payload.destination || "",
    startDate: payload.startDate || "",
    endDate: payload.endDate || "",
    image: payload.image || "",
    description: payload.description || "",
    photos: Array.isArray(payload.photos) ? payload.photos : [],
    location: payload.location || { lat: 0, lng: 0 }
  };
  trips.push(newTrip);
  saveTrips(trips);
  return res.status(201).json(newTrip);
});

app.post("/trips/:id/photos", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { uri } = req.body || {};
  const idx = trips.findIndex(t => t.id === id);
  if (idx === -1) return res.status(404).json({ error: "Trip not found" });
  if (uri) trips[idx].photos.push(uri);
  saveTrips(trips);
  return res.json({ ok: true, photos: trips[idx].photos });
});

app.post("/uploads", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const fileUrl = `${req.protocol}s://${req.get("host")}/uploads/${req.file.filename}`;
  return res.status(201).json({ url: fileUrl });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`Mock backend running on http://localhost:${PORT}`);
});
