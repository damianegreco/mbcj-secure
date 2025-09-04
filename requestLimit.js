// secure/requestLimit.js
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const requestIp = require('request-ip');

const {
  SLOW_TIME_MIN, SLOW_REQUEST, SLOW_DELAY, 
  BAN_TIME_MIN, BAN_REQUEST, BAN_TIMEOUT
} = process.env;

function identificarUsuario(req) {
  // Usamos request-ip para obtener la IP real, incluso detrás de un proxy.
  return requestIp.getClientIp(req) || 'unknown';
}

const bannedUsuarios = new Map();

// Middleware dedicado para bloquear ataques de Path Traversal.
// Debe ejecutarse antes que cualquier otro middleware que procese la URL.
function blockPathTraversal(req, res, next) {
  try {
    // req.originalUrl conserva la URL tal como la envió el cliente (ej: /some/path/../../secret)
    // Usamos decodeURIComponent para detectar patrones codificados (ej: %2e%2e%2f)
    const decodedUrl = decodeURIComponent(req.originalUrl || req.url);

    if (decodedUrl.includes('../')) {
      console.warn(`Ataque de Path Traversal bloqueado desde la IP: ${req.ip}`);
      // Es crucial devolver un 403 Forbidden para este tipo de ataque.
      return res.status(403).send('Forbidden');
    }
  } catch (error) {
    // Si la URL está mal formada (ej. mal uso de %), la bloqueamos por seguridad.
    return res.status(400).send('Bad Request');
  }
  // Si la URL es segura, continuamos con la siguiente capa de middleware.
  next();
}

// Limita las peticiones repetidas para prevenir ataques de fuerza bruta (baneo).
const limiter = rateLimit({
  windowMs: (BAN_TIME_MIN || 5) * 60 * 1000, // Ventana de tiempo (5 minutos por defecto)
  max: (BAN_REQUEST || 300), // Límite de peticiones por ventana de tiempo por IP
  keyGenerator: identificarUsuario,
  standardHeaders: true, // Envía cabeceras `RateLimit-*`
  legacyHeaders: false, // Deshabilita cabeceras `X-RateLimit-*`
  handler: (req, res) => {
    const key = identificarUsuario(req);
    // Añade al usuario a un mapa de baneos temporales.
    bannedUsuarios.set(key, Date.now() + (BAN_TIMEOUT || 15) * 60 * 1000);
    console.error(`Límite de peticiones excedido por: ${key}. Acceso bloqueado.`);
    res.status(429).json({ message: 'Demasiadas solicitudes. Tu acceso ha sido bloqueado temporalmente.' });
  }
});

// Ralentiza las peticiones después de un cierto número, en lugar de bloquearlas.
const speedLimiter = slowDown({
  windowMs: (SLOW_TIME_MIN || 15) * 60 * 1000, // 15 minutos
  delayAfter: (SLOW_REQUEST || 300), // Empieza a ralentizar después de 300 peticiones
  delayMs: (used, req) => {
    const delayAfter = req.slowDown.limit;
    // Añade un delay que incrementa con cada petición extra.
    return (used - delayAfter) * (SLOW_DELAY || 50);
  },
});

function requestLimit() {
  // Middleware para comprobar si un usuario está en el mapa de baneos temporales.
  function checkBan(req, res, next) {
    const key = identificarUsuario(req);
    const banInfo = bannedUsuarios.get(key);
    // Si el usuario está baneado y el tiempo de baneo no ha expirado...
    if (banInfo && Date.now() < banInfo) {
      console.warn(`Petición bloqueada para usuario baneado temporalmente: ${key}`);
      return res.status(429).json({ message: 'Tu acceso fue bloqueado temporalmente por actividad sospechosa.' });
    }
    next();
  }

  // Se devuelve un array de middlewares que se ejecutarán en orden.
  return [
    blockPathTraversal, // 1. Bloqueo de Path Traversal (el más importante)
    checkBan,           // 2. Comprobación de baneos temporales
    speedLimiter,       // 3. Ralentizador de peticiones
    limiter             // 4. Límite de peticiones (baneo)
  ];
}

module.exports = requestLimit;