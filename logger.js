const path = require('path');
const morgan = require('morgan');
const rfs = require('rotating-file-stream');
const fs = require('fs');

/**
 * Crea un middleware de logging para Express.
 * Siempre loguea a archivos rotatorios con formato 'combined'.
 * Si se provee un `mode`, se usa como formato para loguear ADEMÁS en la consola.
 * @param {string} logsPath - Directorio donde se guardarán los logs.
 * @param {string | null} mode - El formato de Morgan para la consola (ej. 'dev', 'tiny', 'short'). Si es null, no se loguea en consola.
 * @returns {function} Middleware de Express.
 */
function logger(logsPath = './logs', mode = null) { 
  if (!fs.existsSync(logsPath)) {
    try {
      fs.mkdirSync(logsPath, { recursive: true });
      console.log(`Directorio de logs creado en: ${logsPath}`);
    } catch (error) {
      console.error('Error al crear el directorio de logs:', error);
      return (req, res, next) => next();
    }
  }

  const accessLogStream = rfs.createStream('access.log', {
    interval: '7d',
    path: logsPath,
    compress: 'gzip',
  });

  const errorLogStream = rfs.createStream('error.log', {
    interval: '7d',
    path: logsPath,
    compress: 'gzip',
  });

  const accessFileLogger = morgan('combined', {
    skip: (req, res) => res.statusCode >= 400,
    stream: accessLogStream,
  });

  const errorFileLogger = morgan('combined', {
    skip: (req, res) => res.statusCode < 400,
    stream: errorLogStream,
  });

  // La variable 'mode' ahora contiene directamente el formato a usar.
  const consoleLogger = mode ? morgan(mode) : null;

  return function (req, res, next) {
    const logToFile = (callback) => {
      accessFileLogger(req, res, (err) => {
        if (err) return callback(err);
        errorFileLogger(req, res, callback);
      });
    };

    if (consoleLogger) {
      // Si hay un logger de consola, lo ejecutamos y luego los de archivo.
      consoleLogger(req, res, (err) => {
        if (err) return next(err);
        logToFile(next);
      });
    } else {
      // Si no, solo ejecutamos los de archivo.
      logToFile(next);
    }
  };
}

module.exports = logger;