// secure/index.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const hpp = require('hpp');
const logger = require('./logger');
const requestLimit = require('./requestLimit');
const customMongoSanitize = require('./sanitizer');
const xssSanitizer = require('./xssSanitizer');

const { BODY_LIMIT } = process.env;

/**
 * Envuelve un middleware para que se salte en las rutas indicadas.
 * Útil para rutas que son proxies puros y no deben consumir el stream
 * del request (body-parsers) antes de que llegue al destino.
 * @param {Function} middleware
 * @param {string[]} excludePaths - Prefijos de ruta a excluir (ej: ['/api'])
 */
function skippable(middleware, excludePaths = []) {
  if (!excludePaths.length) return middleware;
  return (req, res, next) => {
    const url = req.originalUrl || req.url;
    const isExcluded = excludePaths.some(p => url.startsWith(p));
    if (isExcluded) return next();
    return middleware(req, res, next);
  };
}

function secureControl(app, options = {}) {
  const {
    logsPath,
    isDevMode,
    corsOptions,
    SLOW_TIME_MIN,
    SLOW_REQUEST,
    SLOW_DELAY,
    BAN_TIME_MIN,
    BAN_REQUEST,
    excludeBodyParsingPaths = [] // NUEVO
  } = options;

  app.use(logger(logsPath, 'dev'));

  app.set('query parser', 'extended');
  app.set('trust proxy', 1);

  const inDevelopment = String(isDevMode).trim().toLowerCase() === 'true';

  if (!inDevelopment) {
    const rateLimitOptions = {
      SLOW_TIME_MIN: parseInt(SLOW_TIME_MIN, 10) || 15,
      SLOW_REQUEST: parseInt(SLOW_REQUEST, 10) || 300,
      SLOW_DELAY: parseInt(SLOW_DELAY, 10) || 50,
      BAN_TIME_MIN: parseInt(BAN_TIME_MIN, 10) || 5,
      BAN_REQUEST: parseInt(BAN_REQUEST, 10) || 300
    };

    // El rate limiting y el bloqueo de path traversal NO consumen el body,
    // así que se mantienen activos también para las rutas excluidas.
    const limiters = requestLimit(rateLimitOptions);
    app.use(...limiters);
  }

  // MODIFICADO: los body-parsers ahora respetan excludeBodyParsingPaths
  const jsonParser = express.json({ limit: BODY_LIMIT ?? '10kb' });
  const urlencodedParser = express.urlencoded({ extended: true });
  app.use(skippable(jsonParser, excludeBodyParsingPaths));
  app.use(skippable(urlencodedParser, excludeBodyParsingPaths));

  let finalCorsOptions = corsOptions;
  if (corsOptions && corsOptions.origin) {
    finalCorsOptions = {
      ...corsOptions,
      origin: (origin, callback) => {
        const allowedOrigins = Array.isArray(corsOptions.origin)
          ? corsOptions.origin
          : [corsOptions.origin];

        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(null, false);
        }
      },
    };
  }

  app.use(cors(finalCorsOptions));
  app.use(helmet());

  // customMongoSanitize y xssSanitizer dependen de req.body/query/params ya
  // parseados; si la ruta está excluida, req.body será undefined y estos
  // middlewares simplemente no hacen nada (ya tienen guards `if (req.body)`),
  // así que no requieren cambios adicionales.
  app.use(customMongoSanitize);
  app.use(xssSanitizer);

  app.use(hpp());
}

module.exports = { secureControl, logger, requestLimit };