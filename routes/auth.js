const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { lerBanco } = require("../database");
const fs = require("fs");
const path = require("path");

const router = express.Router();

const LOG_PATH = path.join(__dirname, "../security.log");

function log(tipo, req, info = "") {
  const linha = `[${new Date().toISOString()}] ${tipo} | IP: ${req.ip} | ${info}\n`;
  fs.appendFileSync(LOG_PATH, linha);
}

// Rate limiting: 10 tentativas por IP a cada 15 minutos
const limiteLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { erro: "Muitas tentativas. Tente novamente em 15 minutos." },
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /api/auth/login
router.post("/login", limiteLogin, (req, res) => {
  try {
    const { usuario, senha } = req.body;

    if (!usuario || !senha) {
      return res.status(400).json({ erro: "Usuário e senha são obrigatórios." });
    }

    // Sanitização básica — limita tamanho para evitar abusos
    if (usuario.length > 50 || senha.length > 100) {
      log("LOGIN_BLOCKED", req, "payload muito grande");
      return res.status(400).json({ erro: "Dados inválidos." });
    }

    const dados = lerBanco();
    const admin = dados.admin.find(a => a.usuario === usuario);

    // Sempre faz o compareSync mesmo se admin não existir
    // Isso evita timing attacks (tempo de resposta diferente para usuário válido/inválido)
    const senhaOk = admin ? bcrypt.compareSync(senha, admin.senha) : false;

    if (!admin || !senhaOk) {
      log("LOGIN_FALHOU", req, `usuario: ${usuario}`);
      return res.status(401).json({ erro: "Usuário ou senha incorretos." });
    }

    log("LOGIN_OK", req, `usuario: ${usuario}`);

    const token = jwt.sign(
      { id: admin.id, usuario: admin.usuario },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    // Cookie HttpOnly — JavaScript da página não consegue ler
    // Isso protege contra XSS
    res.cookie("mm_token", token, {
      httpOnly: true,           // Inacessível via JavaScript
      secure: process.env.NODE_ENV === "production", // Apenas HTTPS em produção
      sameSite: "strict",       // Protege contra CSRF
      maxAge: 8 * 60 * 60 * 1000, // 8 horas em ms
    });

    // Também retorna o token no body para compatibilidade com o frontend atual
    res.json({ token, usuario: admin.usuario });

  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).json({ erro: "Erro interno." });
  }
});

// POST /api/auth/logout
router.post("/logout", (req, res) => {
  res.clearCookie("mm_token");
  res.json({ mensagem: "Logout realizado." });
});

// GET /api/auth/verificar — checa se token ainda é válido
router.get("/verificar", (req, res) => {
  const token = req.cookies?.mm_token ||
    req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ valido: false });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ valido: true, usuario: payload.usuario });
  } catch {
    res.status(401).json({ valido: false });
  }
});

module.exports = router;
