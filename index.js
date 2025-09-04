// secure/index.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const hpp = require('hpp');
const logger = require('./logger');
const requestLimit = require('./requestLimit');
const customMongoSanitize = require('./sanitizer');
const xssSanitizer = require('./xssSanitizer');

function secureControl(app, options = {}) {
  const { logsPath, isDevMode, corsOptions } = options;

  app.set('query parser', 'extended');
  app.set('trust proxy', 1);
  
  const inDevelopment = String(isDevMode).trim().toLowerCase() === 'true';
  if (!inDevelopment) {
    const limiters = requestLimit();
    app.use(...limiters);
  }

  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true }));

  // CORRECCIÓN: Configuración de CORS más robusta y explícita.
  // Se crea una configuración dinámica si `corsOptions.origin` está definido.
  let finalCorsOptions = corsOptions;
  if (corsOptions && corsOptions.origin) {
    finalCorsOptions = {
      ...corsOptions,
      origin: (origin, callback) => {
        const allowedOrigins = Array.isArray(corsOptions.origin)
          ? corsOptions.origin
          : [corsOptions.origin];

        // Permitimos peticiones sin 'origin' (como las de Postman o CURL)
        // o si el origen está en nuestra lista de permitidos.
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          // No devolvemos un error, simplemente no permitimos el origen.
          // El middleware de CORS se encargará de no enviar la cabecera de acceso.
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
  app.use(logger(logsPath, 'dev'));
}

module.exports = { secureControl, logger, requestLimit };