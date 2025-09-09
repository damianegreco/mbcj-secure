// ejemplo-uso.js
const express = require('express');
const path = require('path');
// Carga las variables de entorno desde el archivo .env
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { secureControl } = require('../index'); // Ajusta la ruta si es necesario

// Se leen TODAS las variables de entorno necesarias en un solo lugar.
const {
  PORT,
  DEVELOP,
  PATH_LOGS,
  // NUEVO: Se añaden las variables para el límite de peticiones
  SLOW_TIME_MIN,
  SLOW_REQUEST,
  SLOW_DELAY,
  BAN_TIME_MIN,
  BAN_REQUEST
} = process.env;

const app = express();

// MODIFICADO: Se construye el objeto de opciones con toda la configuración.
const securityOptions = {
  logsPath: PATH_LOGS,
  isDevMode: DEVELOP,
  
  // Se pasan las configuraciones de rate limiting.
  // No es necesario parsearlas aquí, `secureControl` se encarga de eso.
  SLOW_TIME_MIN,
  SLOW_REQUEST,
  SLOW_DELAY,
  BAN_TIME_MIN,
  BAN_REQUEST
  
  // ELIMINADO: `banFilePath` ya no es necesario porque se eliminó el sistema de baneo manual.
};

// Se llama a secureControl una sola vez con toda la configuración.
secureControl(app, securityOptions);

// Aquí puedes añadir tus rutas y otros middlewares
app.get('/', (req, res) => {
  res.send('Aplicación segura y configurada!');
});

app.listen(PORT || 3000, (error) => {
  if (error) {
    console.error('Error al iniciar el servidor:', error);
    process.exit(1);
  }
  console.log(`✅ Escuchando en el puerto ${PORT || 3000}`);
});

module.exports = app;