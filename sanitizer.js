// secure/sanitizer.js

function removeDollarKeys(data) {
  // Casos base: si no es un objeto o es nulo, es seguro.
  if (data === null || typeof data !== 'object') {
    return data;
  }

  // Si es un array, aplicamos la sanitización a cada elemento.
  if (Array.isArray(data)) {
    return data.map(item => removeDollarKeys(item));
  }

  // Reconstruimos el objeto desde cero para garantizar la limpieza.
  const sanitizedObject = {};

  for (const key in data) {
    // Usamos hasOwnProperty de forma segura para evitar problemas con el prototipo.
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      
      // 1. Si la clave es maliciosa, la omitimos por completo.
      if (key.includes('$')) {
        console.warn(`Clave sospechosa (NoSQL injection) eliminada: ${key}`);
        continue;
      }

      // 2. Sanitizamos el valor de forma recursiva.
      const sanitizedValue = removeDollarKeys(data[key]);
      
      const originalValue = data[key];
      const wasObject = originalValue !== null && typeof originalValue === 'object' && !Array.isArray(originalValue);
      const isNowEmptyObject = sanitizedValue !== null && typeof sanitizedValue === 'object' && !Array.isArray(sanitizedValue) && Object.keys(sanitizedValue).length === 0;

      // 3. Si un objeto que antes tenía contenido ahora está vacío, lo omitimos.
      if (wasObject && Object.keys(originalValue).length > 0 && isNowEmptyObject) {
        continue;
      }
      
      // 4. Si la clave y su valor son seguros, los añadimos al nuevo objeto.
      sanitizedObject[key] = sanitizedValue;
    }
  }

  return sanitizedObject;
}

function customMongoSanitize(req, res, next) {
  // CORRECCIÓN CLAVE: Primero, creamos un clon profundo y limpio de los objetos
  // para eliminar cualquier prototipo anómalo que pueda añadir Express/qs.
  if (req.body) req.body = JSON.parse(JSON.stringify(req.body));
  if (req.query) req.query = JSON.parse(JSON.stringify(req.query));
  if (req.params) req.params = JSON.parse(JSON.stringify(req.params));
  
  // Después, aplicamos la lógica de sanitización sobre los objetos ya limpios.
  if (req.body) req.body = removeDollarKeys(req.body);
  if (req.query) req.query = removeDollarKeys(req.query);
  if (req.params) req.params = removeDollarKeys(req.params);
  
  next();
}

module.exports = customMongoSanitize;