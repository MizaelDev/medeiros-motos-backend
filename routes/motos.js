const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { lerBanco, salvarBanco } = require("../database");
const { autenticar } = require("../middleware/auth");

const router = express.Router();

// ─────────────────────────────────────────────
// UPLOAD DE IMAGENS
// ─────────────────────────────────────────────
const pastaUploads = path.join(__dirname, "../uploads");
if (!fs.existsSync(pastaUploads)) fs.mkdirSync(pastaUploads, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, pastaUploads),
  filename: (req, file, cb) => {
    // Nome aleatório com crypto — não previsível
    const aleatorio = crypto.randomBytes(16).toString("hex");
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `moto_${aleatorio}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const mimetypesPermitidos = ["image/jpeg", "image/png", "image/webp"];
    if (!mimetypesPermitidos.includes(file.mimetype)) {
      return cb(new Error("Apenas JPG, PNG ou WebP são permitidos."));
    }
    const ext = path.extname(file.originalname).toLowerCase();
    const extensoesPermitidas = [".jpg", ".jpeg", ".png", ".webp"];
    if (!extensoesPermitidas.includes(ext)) {
      return cb(new Error("Extensão de arquivo não permitida."));
    }
    cb(null, true);
  },
});

// Verifica magic numbers APÓS o upload (lê os bytes reais do arquivo)
function validarMagicNumber(caminho) {
  const ASSINATURAS = [
    [0xFF, 0xD8, 0xFF],             // JPG
    [0x89, 0x50, 0x4E, 0x47],       // PNG
    [0x52, 0x49, 0x46, 0x46],       // WebP (RIFF)
  ];
  const buffer = Buffer.alloc(4);
  const fd = fs.openSync(caminho, "r");
  fs.readSync(fd, buffer, 0, 4, 0);
  fs.closeSync(fd);
  const bytes = [...buffer];
  return ASSINATURAS.some(assinatura =>
    assinatura.every((b, i) => bytes[i] === b)
  );
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function proximoId(lista) {
  if (lista.length === 0) return 1;
  return Math.max(...lista.map(m => m.id)) + 1;
}

// Valida e sanitiza campos de texto — limita tamanho e remove caracteres perigosos
function sanitizarTexto(valor, maxLen = 200) {
  if (typeof valor !== "string") return "";
  return valor.trim().slice(0, maxLen);
}

// Valida campos numéricos com range definido
function validarNumero(valor, min, max, fallback = 0) {
  const n = parseFloat(valor);
  if (isNaN(n) || !isFinite(n) || n < min || n > max) return fallback;
  return n;
}

// Garante que o caminho do arquivo está dentro da pasta de uploads
// Isso previne Path Traversal
function caminhoSeguro(urlFoto) {
  const caminhoAbsoluto = path.resolve(pastaUploads, path.basename(urlFoto));
  if (!caminhoAbsoluto.startsWith(pastaUploads)) {
    throw new Error("Caminho de arquivo inválido.");
  }
  return caminhoAbsoluto;
}

// ─────────────────────────────────────────────
// ROTAS PÚBLICAS
// ─────────────────────────────────────────────

// GET /api/motos
router.get("/", (req, res) => {
  try {
    const dados = lerBanco();
    res.json([...dados.motos].reverse());
  } catch {
    res.status(500).json({ erro: "Erro ao buscar motos." });
  }
});

// GET /api/motos/:id
router.get("/:id", (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id) || id < 1) return res.status(400).json({ erro: "ID inválido." });

    const dados = lerBanco();
    const moto = dados.motos.find(m => m.id === id);
    if (!moto) return res.status(404).json({ erro: "Moto não encontrada." });

    res.json(moto);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar moto." });
  }
});

// ─────────────────────────────────────────────
// ROTAS PROTEGIDAS (admin)
// ─────────────────────────────────────────────

// POST /api/motos — cadastrar
router.post("/", autenticar, upload.array("fotos", 10), (req, res) => {
  try {
    const { nome, marca, ano, cilindrada, tipo, valor, parcela, km, badge, desc, destaques } = req.body;

    // Validação de campos obrigatórios
    if (!nome || !marca || !ano || !cilindrada || !tipo || !valor) {
      // Remove arquivos enviados se validação falhar
      if (req.files) req.files.forEach(f => fs.unlinkSync(f.path));
      return res.status(400).json({ erro: "Campos obrigatórios: nome, marca, ano, cilindrada, tipo, valor." });
    }

    // Valida magic numbers das imagens enviadas
    const fotosValidas = [];
    for (const arquivo of (req.files || [])) {
      if (!validarMagicNumber(arquivo.path)) {
        fs.unlinkSync(arquivo.path); // Remove arquivo inválido
        return res.status(400).json({ erro: `Arquivo "${arquivo.originalname}" não é uma imagem válida.` });
      }
      fotosValidas.push(`/uploads/${arquivo.filename}`);
    }

    // Badges permitidos (whitelist)
    const badgesPermitidos = ["Nova", "0KM", "Oferta", "Mais Vendida", "Seminova"];
    const badgeSeguro = badgesPermitidos.includes(badge) ? badge : "Nova";

    const dados = lerBanco();
    const novaMoto = {
      id: proximoId(dados.motos),
      nome:       sanitizarTexto(nome, 100),
      marca:      sanitizarTexto(marca, 50),
      ano:        Math.floor(validarNumero(ano, 1900, 2100, 2024)),
      cilindrada: Math.floor(validarNumero(cilindrada, 1, 9999, 0)),
      tipo:       sanitizarTexto(tipo, 50),
      valor:      validarNumero(valor, 0, 10000000, 0),
      parcela:    validarNumero(parcela, 0, 10000000, 0),
      km:         Math.floor(validarNumero(km, 0, 9999999, 0)),
      badge:      badgeSeguro,
      img:        fotosValidas[0] || "",
      fotos:      fotosValidas,
      desc:       sanitizarTexto(desc, 1000),
      destaques:  (destaques || "").split(",").map(d => sanitizarTexto(d, 100)).filter(Boolean).slice(0, 10),
      criado_em:  new Date().toISOString(),
    };

    dados.motos.push(novaMoto);
    salvarBanco(dados);
    res.status(201).json(novaMoto);
  } catch (err) {
    console.error("Erro ao cadastrar:", err.message);
    res.status(500).json({ erro: "Erro ao cadastrar moto." });
  }
});

// PUT /api/motos/:id — editar
router.put("/:id", autenticar, upload.array("fotos", 10), (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id) || id < 1) return res.status(400).json({ erro: "ID inválido." });

    const dados = lerBanco();
    const idx = dados.motos.findIndex(m => m.id === id);
    if (idx === -1) return res.status(404).json({ erro: "Moto não encontrada." });

    const moto = dados.motos[idx];
    const { nome, marca, ano, cilindrada, tipo, valor, parcela, km, badge, desc, destaques, fotosExistentes } = req.body;

    // Parseia fotosExistentes com tratamento de erro
    let fotosAntigas = moto.fotos;
    if (fotosExistentes) {
      try {
        const parsed = JSON.parse(fotosExistentes);
        // Garante que só aceita paths dentro de /uploads
        fotosAntigas = Array.isArray(parsed)
          ? parsed.filter(f => typeof f === "string" && f.startsWith("/uploads/"))
          : moto.fotos;
      } catch {
        fotosAntigas = moto.fotos;
      }
    }

    // Valida magic numbers das novas imagens
    const fotasNovas = [];
    for (const arquivo of (req.files || [])) {
      if (!validarMagicNumber(arquivo.path)) {
        fs.unlinkSync(arquivo.path);
        return res.status(400).json({ erro: `Arquivo "${arquivo.originalname}" não é uma imagem válida.` });
      }
      fotasNovas.push(`/uploads/${arquivo.filename}`);
    }

    const todasFotos = [...fotosAntigas, ...fotasNovas];

    const badgesPermitidos = ["Nova", "0KM", "Oferta", "Mais Vendida", "Seminova"];
    const badgeSeguro = badgesPermitidos.includes(badge) ? badge : moto.badge;

    dados.motos[idx] = {
      ...moto,
      nome:       nome       ? sanitizarTexto(nome, 100)       : moto.nome,
      marca:      marca      ? sanitizarTexto(marca, 50)        : moto.marca,
      ano:        ano        ? Math.floor(validarNumero(ano, 1900, 2100, moto.ano))           : moto.ano,
      cilindrada: cilindrada ? Math.floor(validarNumero(cilindrada, 1, 9999, moto.cilindrada)): moto.cilindrada,
      tipo:       tipo       ? sanitizarTexto(tipo, 50)         : moto.tipo,
      valor:      valor      ? validarNumero(valor, 0, 10000000, moto.valor)                  : moto.valor,
      parcela:    parcela    ? validarNumero(parcela, 0, 10000000, moto.parcela)              : moto.parcela,
      km:         km != null ? Math.floor(validarNumero(km, 0, 9999999, moto.km))            : moto.km,
      badge:      badgeSeguro,
      img:        todasFotos[0] || moto.img,
      fotos:      todasFotos,
      desc:       desc != null ? sanitizarTexto(desc, 1000) : moto.desc,
      destaques:  destaques
        ? destaques.split(",").map(d => sanitizarTexto(d, 100)).filter(Boolean).slice(0, 10)
        : moto.destaques,
    };

    salvarBanco(dados);
    res.json(dados.motos[idx]);
  } catch (err) {
    console.error("Erro ao editar:", err.message);
    res.status(500).json({ erro: "Erro ao editar moto." });
  }
});

// DELETE /api/motos/:id — excluir
router.delete("/:id", autenticar, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id) || id < 1) return res.status(400).json({ erro: "ID inválido." });

    const dados = lerBanco();
    const moto = dados.motos.find(m => m.id === id);
    if (!moto) return res.status(404).json({ erro: "Moto não encontrada." });

    // Remove fotos — validando cada caminho antes de deletar
    moto.fotos.forEach(foto => {
      try {
        const caminho = caminhoSeguro(foto);
        if (fs.existsSync(caminho)) fs.unlinkSync(caminho);
      } catch (err) {
        console.error("Caminho inválido ignorado:", foto);
      }
    });

    dados.motos = dados.motos.filter(m => m.id !== id);
    salvarBanco(dados);
    res.json({ mensagem: "Moto removida com sucesso." });
  } catch (err) {
    res.status(500).json({ erro: "Erro ao excluir moto." });
  }
});

// DELETE /api/motos/:id/foto — remover foto específica
router.delete("/:id/foto", autenticar, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id) || id < 1) return res.status(400).json({ erro: "ID inválido." });

    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ erro: "URL da foto é obrigatória." });
    }

    // Garante que a URL começa com /uploads/ — previne Path Traversal
    if (!url.startsWith("/uploads/")) {
      return res.status(400).json({ erro: "URL de foto inválida." });
    }

    const dados = lerBanco();
    const idx = dados.motos.findIndex(m => m.id === id);
    if (idx === -1) return res.status(404).json({ erro: "Moto não encontrada." });

    // Valida o caminho antes de deletar
    const caminho = caminhoSeguro(url);
    if (fs.existsSync(caminho)) fs.unlinkSync(caminho);

    dados.motos[idx].fotos = dados.motos[idx].fotos.filter(f => f !== url);
    dados.motos[idx].img = dados.motos[idx].fotos[0] || "";
    salvarBanco(dados);

    res.json({ mensagem: "Foto removida.", fotos: dados.motos[idx].fotos });
  } catch (err) {
    if (err.message === "Caminho de arquivo inválido.") {
      return res.status(400).json({ erro: err.message });
    }
    res.status(500).json({ erro: "Erro ao remover foto." });
  }
});

module.exports = router;
