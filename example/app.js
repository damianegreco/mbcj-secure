const express = require('express');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { secureControl } = require('../index');

const { PORT, DEVELOP, PATH_LOGS, PATH_BAN } = process.env;

const app = express();

// Llama a secureControl y le pasas la app y las opciones para que la configure
secureControl(app, {
  logsPath: PATH_LOGS,
  banFilePath: PATH_BAN,
  isDevMode: DEVELOP
});

// Aquí puedes añadir tus rutas y otros middlewares
app.get('/', (req, res) => {
  res.send('Aplicación segura y configurada!');
});

app.listen(PORT, (error) => {
  if (error) {
    console.error(error);
    process.exit(1);
  }
  console.log(`✅ Escuchando en el puerto ${PORT}`);
});

module.exports = app;