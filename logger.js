const morgan = require('morgan');
const rfs = require('rotating-file-stream');
const fs = require('fs');

/**
 * Crea y configura un conjunto de middlewares de logging para Express utilizando Morgan.
 *
 * Genera logs de acceso y error en archivos rotatorios (`access.log`, `error.log`)
 * en el directorio especificado. Opcionalmente, puede también loguear en la consola
 * si se proporciona un formato.
 *
 * @param {string} [logsPath='./logs'] - Directorio donde se guardarán los archivos de log.
 * @param {string | null} [mode=null] - Formato de Morgan para la consola ('dev', 'tiny', etc.). Si es null, no se loguea en consola.
 * @returns {Array<Function>} Un array de middlewares de Express. Debe usarse con el operador de propagación (spread operator): `app.use(...logger())`.
 */
function logger(logsPath = './logs', mode = null) {
  // Asegura que el directorio de logs exista.
  if (!fs.existsSync(logsPath)) {
    try {
      fs.mkdirSync(logsPath, { recursive: true });
      console.log(`Directorio de logs creado en: ${logsPath}`);
    } catch (error) {
      console.error('Error crítico al crear el directorio de logs:', error);
      // Devuelve un middleware no-op si no se puede loguear.
      return [(req, res, next) => next()];
    }
  }

  // Flujo de escritura para logs de acceso (status < 400)
  const accessLogStream = rfs.createStream('access.log', {
    interval: '7d', // Rota cada 7 días
    path: logsPath,
    compress: 'gzip' // Comprime los archivos rotados
  });

  // Flujo de escritura para logs de error (status >= 400)
  const errorLogStream = rfs.createStream('error.log', {
    interval: '7d',
    path: logsPath,
    compress: 'gzip'
  });

  const middlewares = [];

  // Añade el logger de consola solo si se especifica un modo.
  if (mode) {
    middlewares.push(morgan(mode));
  }

  // Logger de archivo para peticiones exitosas.
  middlewares.push(morgan('combined', {
    skip: (req, res) => res.statusCode >= 400,
    stream: accessLogStream
  }));

  // Logger de archivo para peticiones con error.
  middlewares.push(morgan('combined', {
    skip: (req, res) => res.statusCode < 400,
    stream: errorLogStream
  }));

  return middlewares;
}

module.exports = logger;