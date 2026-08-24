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

/**
 * Aplica la configuracion de seguridad estandar sobre una app de Express:
 * logging, rate limiting, cabeceras de helmet, CORS, sanitizacion y HPP.
 *
 * @param {import('express').Application} app
 * @param {object}   [options]
 * @param {string}   [options.logsPath]                 - Carpeta donde se escriben los logs.
 * @param {boolean}  [options.isDevMode]                - En modo desarrollo se omite el rate limiting.
 * @param {object}   [options.corsOptions]              - Opciones de CORS.
 * @param {string[]} [options.excludeBodyParsingPaths]  - Prefijos de ruta que no deben pasar por los body-parsers.
 * @param {string[]} [options.wasmPaths]                - Prefijos de ruta donde se permite compilar WebAssembly.
 *                                                        Agrega `'wasm-unsafe-eval'` a `script-src` solo en esas
 *                                                        rutas; el resto de la aplicacion mantiene la CSP base.
 *                                                        Pensado para los fronts que leen codigos con la camara.
 *
 * @example
 * secureControl(app, {
 *   logsPath: PATH_LOGS,
 *   isDevMode: DEVELOP === 'true',
 *   // Solo estos fronts pueden instanciar WebAssembly:
 *   wasmPaths: ['/policia', '/morosos']
 * });
 */
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
    excludeBodyParsingPaths = [], // NUEVO
    wasmPaths = []
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

  // WebAssembly queda deshabilitado en toda la aplicacion por la CSP base:
  // compilarlo exige 'wasm-unsafe-eval' dentro de script-src, y habilitarlo de
  // forma global ampliaria la superficie de ataque de los sistemas que no lo
  // usan. Por eso la politica se relaja unicamente en las rutas declaradas en
  // `wasmPaths` — tipicamente los fronts que leen el DNI con la camara, cuyo
  // lector de codigos corre sobre WASM.
  //
  // Se registra despues del helmet global a proposito: al tratarse de la misma
  // cabecera, esta CSP pisa a la anterior solo en esas rutas.
  if (wasmPaths.length > 0) {
    const scriptSrcBase = helmet.contentSecurityPolicy.getDefaultDirectives()['script-src'];

    app.use(wasmPaths, helmet.contentSecurityPolicy({
      useDefaults: true,
      directives: {
        scriptSrc: [...scriptSrcBase, "'wasm-unsafe-eval'"]
      }
    }));
  }

  // customMongoSanitize y xssSanitizer dependen de req.body/query/params ya
  // parseados; si la ruta está excluida, req.body será undefined y estos
  // middlewares simplemente no hacen nada (ya tienen guards `if (req.body)`),
  // así que no requieren cambios adicionales.
  app.use(customMongoSanitize);
  app.use(xssSanitizer);

  app.use(hpp());
}

module.exports = { secureControl, logger, requestLimit };