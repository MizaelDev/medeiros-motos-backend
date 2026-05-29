const jwt = require("jsonwebtoken");

// Middleware que protege as rotas do admin
// Aceita token via cookie HttpOnly OU via header Authorization
function autenticar(req, res, next) {
  // Tenta pegar do cookie primeiro (mais seguro)
  const tokenCookie = req.cookies?.mm_token;
  // Fallback para header Authorization (compatibilidade)
  const tokenHeader = req.headers["authorization"]?.split(" ")[1];

  const token = tokenCookie || tokenHeader;

  if (!token) {
    return res.status(401).json({ erro: "Acesso negado. Faça login." });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = payload;
    next();
  } catch (err) {
    return res.status(401).json({ erro: "Token inválido ou expirado. Faça login novamente." });
  }
}

module.exports = { autenticar };
