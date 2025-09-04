// secure/xssSanitizer.js
const sanitizeHtml = require('sanitize-html');

const sanitizeObject = (data) => {
  // Caso base: si es un string, lo sanitizamos.
  if (typeof data === 'string') {
    return sanitizeHtml(data, { allowedTags: [], allowedAttributes: {} });
  }

  if (data === null || typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeObject(item));
  }
  
  const sanitizedData = {};
  for (const key in data) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      sanitizedData[key] = sanitizeObject(data[key]);
    }
  }
  return sanitizedData;
};

function xssSanitizer(req, res, next) {
  // CORRECCIÓN CLAVE: Clonado profundo para asegurar que trabajamos con objetos estándar.
  if (req.body) req.body = JSON.parse(JSON.stringify(req.body));
  if (req.query) req.query = JSON.parse(JSON.stringify(req.query));
  if (req.params) req.params = JSON.parse(JSON.stringify(req.params));

  // Aplicamos la sanitización XSS.
  if (req.body) req.body = sanitizeObject(req.body);
  if (req.query) req.query = sanitizeObject(req.query);
  if (req.params) req.params = sanitizeObject(req.params);
  next();
}

module.exports = xssSanitizer;