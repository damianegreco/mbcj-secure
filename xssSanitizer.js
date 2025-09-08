// secure/xssSanitizer.js
const sanitizeHtml = require('sanitize-html');

/**
 * Sanitiza recursivamente un objeto o array para eliminar etiquetas HTML de todas sus propiedades de tipo string.
 * @param {any} data - El dato (objeto, array, string, etc.) a sanitizar.
 * @returns {any} El dato sanitizado.
 */
const sanitizeObject = (data) => {
  if (typeof data === 'string') return sanitizeHtml(data, { allowedTags: [], allowedAttributes: {} });
  if (data === null || typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map(item => sanitizeObject(item));

  const sanitizedData = {};
  for (const key in data) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      sanitizedData[key] = sanitizeObject(data[key]);
    }
  }
  return sanitizedData;
};

/**
 * Middleware de Express para sanitizar `req.body`, `req.query` y `req.params`
 * y así prevenir ataques de Cross-Site Scripting (XSS).
 * Clona profundamente cada objeto para asegurar que se trabaja con datos estándar.
 * @param {import('express').Request} req - El objeto de solicitud de Express.
 * @param {import('express').Response} res - El objeto de respuesta de Express.
 * @param {import('express').NextFunction} next - La función para pasar al siguiente middleware.
 * @returns {void}
 */
function xssSanitizer(req, res, next) {
  if (req.body) req.body = JSON.parse(JSON.stringify(req.body));
  if (req.query) req.query = JSON.parse(JSON.stringify(req.query));
  if (req.params) req.params = JSON.parse(JSON.stringify(req.params));

  if (req.body) req.body = sanitizeObject(req.body);
  if (req.query) req.query = sanitizeObject(req.query);
  if (req.params) req.params = sanitizeObject(req.params);

  next();
}

module.exports = xssSanitizer;