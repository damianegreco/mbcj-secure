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
 * Aplica una capa de seguridad integral a una aplicación Express.
 * @param {import('express').Application} app - La instancia de la aplicación Express.
 * @param {object} [options={}] - Objeto de configuración.
 */
function secureControl(app, options = {}) {
  // Se destructuran todas las opciones, incluidas las de rate limiting.
  const {
    logsPath,
    isDevMode,
    corsOptions,
    SLOW_TIME_MIN,
    SLOW_REQUEST,
    SLOW_DELAY,
    BAN_TIME_MIN,
    BAN_REQUEST
  } = options;

  app.use(logger(logsPath, 'dev'));

  app.set('query parser', 'extended');
  app.set('trust proxy', 1);

  const inDevelopment = String(isDevMode).trim().toLowerCase() === 'true';
  
  // Solo se aplica el rate limiting si no estamos en modo de desarrollo.
  if (!inDevelopment) {
    // NUEVO: Se prepara el objeto de configuración para requestLimit.
    // Aquí se realiza el parseo de string a número y se asignan valores por defecto.
    const rateLimitOptions = {
      SLOW_TIME_MIN: parseInt(SLOW_TIME_MIN, 10) || 15,
      SLOW_REQUEST: parseInt(SLOW_REQUEST, 10) || 300,
      SLOW_DELAY: parseInt(SLOW_DELAY, 10) || 50,
      BAN_TIME_MIN: parseInt(BAN_TIME_MIN, 10) || 5,
      BAN_REQUEST: parseInt(BAN_REQUEST, 10) || 300
    };

    // MODIFICADO: Se pasa el objeto de opciones a la función requestLimit.
    const limiters = requestLimit(rateLimitOptions);
    app.use(...limiters);
  }

  app.use(express.json({ limit: BODY_LIMIT ?? '10kb' }));
  app.use(express.urlencoded({ extended: true }));

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

  app.use(customMongoSanitize);
  app.use(xssSanitizer);

  app.use(hpp());
}

module.exports = { secureControl, logger, requestLimit };