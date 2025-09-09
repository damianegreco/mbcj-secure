// secure/requestLimit.js
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const requestIp = require('request-ip');

/**
 * Obtiene la dirección IP real del cliente.
 * @param {import('express').Request} req
 * @returns {string}
 */
function identificarUsuario(req) {
  return requestIp.getClientIp(req) || 'unknown';
}

/**
 * Middleware para bloquear ataques de Path Traversal.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function blockPathTraversal(req, res, next) {
  try {
    const decodedUrl = decodeURIComponent(req.originalUrl || req.url);
    if (decodedUrl.includes('../')) {
      console.warn(`Ataque de Path Traversal bloqueado desde la IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }
  } catch (error) {
    console.warn(`URL mal formada bloqueada desde la IP: ${req.ip}`);
    return res.status(400).send('Bad Request');
  }
  next();
}

/**
 * Ensambla y devuelve una cadena de middlewares de seguridad.
 * @param {object} [options={}] - Objeto de configuración para los límites.
 * @param {number} [options.SLOW_TIME_MIN=15] - Ventana de tiempo en minutos para `slowDown`.
 * @param {number} [options.SLOW_REQUEST=300] - Número de peticiones antes de empezar a ralentizar.
 * @param {number} [options.SLOW_DELAY=50] - Milisegundos de retraso a añadir por cada petición extra.
 * @param {number} [options.BAN_TIME_MIN=5] - Ventana de tiempo en minutos para `rateLimit`.
 * @param {number} [options.BAN_REQUEST=300] - Número máximo de peticiones antes de bloquear.
 * @returns {Array<Function>} Un array de middlewares para ser usado en Express.
 */
function requestLimit(options = {}) {
  // Se destructuran las opciones y se asignan valores por defecto si no se proporcionan.
  const {
    SLOW_TIME_MIN = 15,
    SLOW_REQUEST = 300,
    SLOW_DELAY = 50,
    BAN_TIME_MIN = 5,
    BAN_REQUEST = 300
    // BAN_TIMEOUT ya no es necesario porque se eliminó la lógica de baneo manual.
  } = options;

  /**
   * Middleware que ralentiza las peticiones.
   */
  const speedLimiter = slowDown({
    windowMs: SLOW_TIME_MIN * 60 * 1000,
    delayAfter: SLOW_REQUEST,
    delayMs: (used, req) => {
      const delayAfter = req.slowDown.limit;
      return (used - delayAfter) * SLOW_DELAY;
    },
    keyGenerator: identificarUsuario
  });

  /**
   * Middleware que limita las peticiones repetidas.
   */
  const limiter = rateLimit({
    windowMs: BAN_TIME_MIN * 60 * 1000,
    max: BAN_REQUEST,
    keyGenerator: identificarUsuario,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      const key = identificarUsuario(req);
      console.error(`Límite de peticiones excedido por: ${key}. Peticiones bloqueadas por los próximos ${BAN_TIME_MIN} min.`);
      res.status(429).json({ message: `Demasiadas solicitudes. Inténtalo de nuevo en ${BAN_TIME_MIN} minutos.` });
    }
  });

  // Devuelve los middlewares en el orden correcto.
  return [
    blockPathTraversal,
    limiter,
    speedLimiter
  ];
}

module.exports = requestLimit;