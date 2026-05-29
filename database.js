const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const DB_PATH = path.join(__dirname, "data.json");

function lerBanco() {
  if (!fs.existsSync(DB_PATH)) {
    return { motos: [], admin: [] };
  }
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    console.error("❌ Erro ao ler data.json — arquivo corrompido.");
    return { motos: [], admin: [] };
  }
}

function salvarBanco(dados) {
  // Salva em arquivo temporário primeiro, depois renomeia
  // Isso evita corromper o banco se o processo for interrompido no meio da escrita
  const tmp = DB_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(dados, null, 2), "utf8");
  fs.renameSync(tmp, DB_PATH);
}

function inicializarBanco() {
  const dados = lerBanco();

  if (dados.admin.length === 0) {
    const senha = process.env.ADMIN_PASSWORD || "admin123";
    const senhaHash = bcrypt.hashSync(senha, 12);
    dados.admin.push({ id: 1, usuario: "admin", senha: senhaHash });
    salvarBanco(dados);
    // NUNCA loga a senha em plaintext — só confirma que foi criado
    console.log("✅ Usuário admin criado com sucesso.");
  }

  console.log("✅ Banco de dados inicializado.");
}

module.exports = { lerBanco, salvarBanco, inicializarBanco };
