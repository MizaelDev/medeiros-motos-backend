require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const { inicializarBanco } = require("./database");

const app = express();
const PORT = process.env.PORT || 3001;

// ─────────────────────────────────────────────
// VALIDAÇÃO DO JWT_SECRET
// ─────────────────────────────────────────────
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error("❌ JWT_SECRET inválido ou muito curto (mínimo 32 caracteres).");
  console.error("   Gere um com: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
  process.exit(1);
}

// ─────────────────────────────────────────────
// TRUST PROXY — necessário no Railway
// Garante que req.ip retorna o IP real do usuário
// e não o IP do proxy, tornando o rate limiting eficaz
// ─────────────────────────────────────────────
app.set("trust proxy", 1);

// ─────────────────────────────────────────────
// HELMET — headers de segurança
// ─────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
    },
  },
}));

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:5173"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Bloqueado por CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

// ─────────────────────────────────────────────
// RATE LIMITING GLOBAL
// Protege todas as rotas contra DoS
// ─────────────────────────────────────────────
const limitadorGlobal = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 200,                  // máximo 200 requisições por IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: "Muitas requisições. Tente novamente em 15 minutos." },
});
app.use(limitadorGlobal);

// ─────────────────────────────────────────────
// PARSE DO BODY E COOKIES
// ─────────────────────────────────────────────
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(cookieParser());

// ─────────────────────────────────────────────
// LOGS DE SEGURANÇA
// ─────────────────────────────────────────────
const LOG_PATH = path.join(__dirname, "security.log");

function logSeguranca(tipo, req, info = "") {
  const linha = `[${new Date().toISOString()}] ${tipo} | IP: ${req.ip} | ${req.method} ${req.path} | ${info}\n`;
  fs.appendFileSync(LOG_PATH, linha);
}

app.use((req, res, next) => {
  if (req.path.startsWith("/api/auth")) {
    logSeguranca("AUTH_REQUEST", req, `usuario: ${req.body?.usuario || "-"}`);
  }
  next();
});

app.locals.logSeguranca = logSeguranca;

// ─────────────────────────────────────────────
// ARQUIVOS ESTÁTICOS
// ─────────────────────────────────────────────
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.get("/", (req, res) => {
  res.json({ 
    mensagem: "Bem-vindo à API Medeiros Motos", 
    status: "online",
    documentacao: "https://seu-projeto.up.railway.app/health" 
  });
});
// ─────────────────────────────────────────────
// ROTAS
// ─────────────────────────────────────────────
app.use("/api/auth", require("./routes/auth"));
app.use("/api/motos", require("./routes/motos"));

app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// 404 E HANDLER DE ERROS
// ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ erro: "Rota não encontrada." });
});

app.use((err, req, res, next) => {
  console.error("Erro:", err.message);
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({ erro: "Arquivo muito grande. Máximo 5MB." });
  }
  res.status(500).json({ erro: "Erro interno do servidor." });
});

// ─────────────────────────────────────────────
// INICIALIZAÇÃO
// ─────────────────────────────────────────────
inicializarBanco();

app.listen(PORT, () => {
  console.log(`🏍️  Medeiros Motos API rodando na porta ${PORT}`);
});
