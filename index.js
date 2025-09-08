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

function secureControl(app, options = {}) {
  const { logsPath, isDevMode, corsOptions } = options;
  app.use(logger(logsPath, 'dev'));

  app.set('query parser', 'extended');
  app.set('trust proxy', 1);
  
  const inDevelopment = String(isDevMode).trim().toLowerCase() === 'true';
  if (!inDevelopment) {
    const limiters = requestLimit();
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