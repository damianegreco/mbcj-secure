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
 * Aplica una configuración de seguridad y logging robusta a una aplicación Express.
 * Incluye Helmet, CORS, HPP, sanitización de NoSQL/XSS, limitación de peticiones y logging.
 *
 * @param {import('express').Application} app - La instancia de la aplicación Express.
 * @param {object} [options={}] - Opciones de configuración.
 * @param {string} [options.logsPath] - Ruta para guardar los archivos de log.
 * @param {boolean} [options.isDevMode=false] - Si es `true`, activa el logging en consola y deshabilita los límites de peticiones.
 * @param {import('cors').CorsOptions} [options.corsOptions] - Objeto de configuración para el middleware CORS.
 * @returns {void}
 */
function secureControl(app, options = {}) {
  const { logsPath, isDevMode, corsOptions } = options;
  const inDevelopment = String(isDevMode).trim().toLowerCase() === 'true';

  // 1. Logging (debe ser de los primeros para registrar todo).
  // Usa 'dev' para la consola solo en desarrollo, y siempre loguea a archivo.
  app.use(logger(logsPath, inDevelopment ? 'dev' : null));

  // 2. Configuraciones de confianza del proxy y parsing.
  app.set('trust proxy', 1);

  // 3. Middlewares de seguridad (solo en producción).
  if (!inDevelopment) app.use(...requestLimit());

  // 4. Body Parsers (necesarios antes de los sanitizers y HPP).
  app.use(express.json({ limit: BODY_LIMIT ?? '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: BODY_LIMIT ?? '10kb' }));

  // 5. Configuración de CORS con una lista blanca dinámica.
  let finalCorsOptions = corsOptions;
  if (corsOptions && corsOptions.origin) {
    finalCorsOptions = {
      ...corsOptions,
      origin: (origin, callback) => {
        const allowedOrigins = Array.isArray(corsOptions.origin)
          ? corsOptions.origin
          : [corsOptions.origin];
        // Permite peticiones sin 'origin' (ej. Postman, server-to-server) o que estén en la lista blanca.
        callback(null, !origin || allowedOrigins.includes(origin));
      }
    };
  }
  app.use(cors(finalCorsOptions));

  // 6. Cabeceras de seguridad y sanitizadores.
  app.use(helmet());
  app.use(customMongoSanitize);
  app.use(xssSanitizer);

  // 7. Protección contra polución de parámetros HTTP (debe ir después de los parsers).
  app.use(hpp());
}

module.exports = { secureControl, logger, requestLimit };