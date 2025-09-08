// secure/requestLimit.js
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const requestIp = require('request-ip');

const {
  SLOW_TIME_MIN, SLOW_REQUEST, SLOW_DELAY,
  BAN_TIME_MIN, BAN_REQUEST, BAN_TIMEOUT
} = process.env;

/**
 * Obtiene la dirección IP real del cliente, incluso si está detrás de un proxy.
 * @param {import('express').Request} req - El objeto de solicitud de Express.
 * @returns {string} La dirección IP del cliente o 'unknown' si no se puede determinar.
 */
function identificarUsuario(req) {
  return requestIp.getClientIp(req) || 'unknown';
}

/**
 * @type {Map<string, number>}
 * Mapa en memoria para almacenar las IPs de usuarios baneados temporalmente.
 * La clave es la IP y el valor es el timestamp de cuando expira el baneo.
 * Nota: Al ser en memoria, los baneos se reiniciarán si el servidor se reinicia.
 */
const bannedUsuarios = new Map();

/**
 * Middleware de Express para bloquear ataques de Path Traversal (`../`).
 * Debe ejecutarse antes que cualquier otro middleware que procese la URL.
 * @param {import('express').Request} req - El objeto de solicitud de Express.
 * @param {import('express').Response} res - El objeto de respuesta de Express.
 * @param {import('express').NextFunction} next - La función para pasar al siguiente middleware.
 * @returns {void}
 */
function blockPathTraversal(req, res, next) {
  try {
    const decodedUrl = decodeURIComponent(req.originalUrl || req.url);
    if (decodedUrl.includes('../')) {
      console.warn(`Ataque de Path Traversal bloqueado desde la IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }
  } catch (error) {
    // Si la decodificación falla (ej. URL mal formada), se considera un mal intento.
    console.warn(`URL mal formada bloqueada desde la IP: ${req.ip}`);
    return res.status(400).send('Bad Request');
  }
  next();
}

/**
 * Middleware que limita las peticiones repetidas para prevenir ataques de fuerza bruta.
 * Si se supera el límite, el usuario es añadido al mapa de baneos.
 */
const limiter = rateLimit({
  windowMs: (BAN_TIME_MIN || 5) * 60 * 1000,
  max: (BAN_REQUEST || 300),
  keyGenerator: identificarUsuario,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const key = identificarUsuario(req);
    const banTimeout = (BAN_TIMEOUT || 15) * 60 * 1000;
    bannedUsuarios.set(key, Date.now() + banTimeout);
    console.error(`Límite de peticiones excedido por: ${key}. Acceso bloqueado por ${BAN_TIMEOUT || 15} min.`);
    res.status(429).json({ message: 'Demasiadas solicitudes. Tu acceso ha sido bloqueado temporalmente.' });
  }
});

/**
 * Middleware que ralentiza las peticiones después de un cierto número en una ventana de tiempo,
 * como medida de mitigación antes de un bloqueo completo.
 */
const speedLimiter = slowDown({
  windowMs: (SLOW_TIME_MIN || 15) * 60 * 1000,
  delayAfter: (SLOW_REQUEST || 300),
  delayMs: (used, req) => {
    const delayAfter = req.slowDown.limit;
    return (used - delayAfter) * (SLOW_DELAY || 50);
  },
  keyGenerator: identificarUsuario
});

/**
 * Factory function que ensambla y devuelve una cadena de middlewares de seguridad.
 * El orden es crucial para la efectividad:
 * 1. Bloqueo de Path Traversal.
 * 2. Verificación de baneos existentes.
 * 3. Ralentización de peticiones sospechosas.
 * 4. Límite de peticiones que puede resultar en un baneo.
 * @returns {Array<Function>} Un array de middlewares para ser usado en Express.
 */
function requestLimit() {
  /**
   * Middleware interno para comprobar si un usuario está actualmente en el mapa de baneos.
   * @param {import('express').Request} req - El objeto de solicitud de Express.
   * @param {import('express').Response} res - El objeto de respuesta de Express.
   * @param {import('express').NextFunction} next - La función para pasar al siguiente middleware.
   */
  function checkBan(req, res, next) {
    const key = identificarUsuario(req);
    const banExpiration = bannedUsuarios.get(key);
    if (banExpiration && Date.now() < banExpiration) {
      console.warn(`Petición bloqueada para usuario baneado temporalmente: ${key}`);
      return res.status(429).json({ message: 'Tu acceso fue bloqueado temporalmente por actividad sospechosa.' });
    }
    // Si el baneo ha expirado, se elimina del mapa.
    if (banExpiration && Date.now() >= banExpiration) {
      bannedUsuarios.delete(key);
    }
    next();
  }

  return [
    blockPathTraversal,
    checkBan,
    speedLimiter,
    limiter
  ];
}

module.exports = requestLimit;