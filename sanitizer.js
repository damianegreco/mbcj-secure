// secure/sanitizer.js

/**
 * Sanitiza recursivamente un objeto o array para eliminar claves que contengan el carácter '$',
 * previniendo así ataques de inyección NoSQL. También elimina cualquier objeto que quede
 * vacío después de que sus claves maliciosas hayan sido eliminadas.
 * @param {any} data - El dato (objeto, array, etc.) a sanitizar.
 * @returns {any} El dato sanitizado, libre de claves con '$'.
 */
function removeDollarKeys(data) {
  if (data === null || typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map(item => removeDollarKeys(item));

  const sanitizedObject = {};
  for (const key in data) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      if (key.includes('$')) {
        console.warn(`Clave sospechosa (NoSQL injection) eliminada: ${key}`);
        continue;
      }

      const originalValue = data[key];
      const sanitizedValue = removeDollarKeys(originalValue);
      
      const wasObject = originalValue !== null && typeof originalValue === 'object' && !Array.isArray(originalValue);
      const isNowEmptyObject = sanitizedValue !== null && typeof sanitizedValue === 'object' && !Array.isArray(sanitizedValue) && Object.keys(sanitizedValue).length === 0;

      // Si un objeto que antes tenía contenido ahora está vacío tras la sanitización, se omite.
      if (wasObject && Object.keys(originalValue).length > 0 && isNowEmptyObject) continue;
      
      sanitizedObject[key] = sanitizedValue;
    }
  }

  return sanitizedObject;
}

/**
 * Middleware de Express para sanitizar `req.body`, `req.query` y `req.params`
 * eliminando claves que contengan el carácter '$' para prevenir inyecciones NoSQL.
 * @param {import('express').Request} req - El objeto de solicitud de Express.
 * @param {import('express').Response} res - El objeto de respuesta de Express.
 * @param {import('express').NextFunction} next - La función para pasar al siguiente middleware.
 * @returns {void}
 */
function customMongoSanitize(req, res, next) {
  if (req.body) req.body = JSON.parse(JSON.stringify(req.body));
  if (req.query) req.query = JSON.parse(JSON.stringify(req.query));
  if (req.params) req.params = JSON.parse(JSON.stringify(req.params));
  
  if (req.body) req.body = removeDollarKeys(req.body);
  if (req.query) req.query = removeDollarKeys(req.query);
  if (req.params) req.params = removeDollarKeys(req.params);
  
  next();
}

module.exports = customMongoSanitize;