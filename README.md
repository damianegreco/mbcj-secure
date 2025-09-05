# Secure Middleware para Express.js (mbcj-secure)

[![Estado de las Pruebas](https://img.shields.io/badge/pruebas-aprobadas-green)](./test-report/report.html)
[![Cobertura de Código](https://img.shields.io/badge/cobertura-95%25-brightgreen)](./test-report/coverage/lcov-report/index.html)
[![NPM Version](https://img.shields.io/npm/v/mbcj-secure.svg)](https://www.npmjs.com/package/mbcj-secure)
[![Licencia](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

## Descripción del Proyecto

**mbcj-secure** es un conjunto de herramientas de seguridad para aplicaciones web construidas con Express.js. Su propósito es proporcionar una capa de protección robusta y fácil de implementar contra vulnerabilidades comunes como Cross-Site Scripting (XSS), ataques de fuerza bruta y la inyección de datos maliciosos.

Este paquete integra varias estrategias de seguridad, incluyendo la configuración de cabeceras HTTP seguras, limitación de peticiones (rate limiting) y sanitización de datos de entrada, todo ello gestionado a través de un middleware modular y configurable.

---

## Características y Funcionalidades

-   **Cabeceras de Seguridad HTTP**: Utiliza `helmet` para configurar cabeceras HTTP que protegen la aplicación contra ataques como clickjacking, XSS y otros.
-   **Sanitización de XSS**: Limpia los datos de entrada en `req.body`, `req.query` y `req.params` para neutralizar scripts maliciosos y prevenir ataques de Cross-Site Scripting (XSS).
-   **Sanitización de Entradas**: Elimina caracteres maliciosos y operadores de consulta (ej. `$`, `.`) de los datos de entrada para prevenir ataques de inyección NoSQL.
-   **Limitador de Peticiones (Rate Limiter)**: Restringe el número de peticiones que un cliente puede hacer a la API en un período determinado, ayudando a mitigar ataques de fuerza bruta.
-   **Registro (Logging)**: Genera logs de acceso y errores para monitorizar la actividad de la aplicación y detectar comportamientos anómalos.
-   **Configuración Flexible**: Permite personalizar las opciones del middleware a través de variables de entorno o un objeto de configuración.

---

## Estructura del Proyecto

El repositorio está organizado de la siguiente manera para separar las responsabilidades y facilitar el mantenimiento:

```
/
├── __tests__/              # Contiene las pruebas unitarias y de integración.
│   ├── 1-securityHeaders.test.js
│   ├── 2-sanitizers.test.js
│   └── 3-requestLimit.test.js
│
├── example/                # Ejemplo de implementación en una aplicación Express.
│   ├── app.js
│   └── .env
│
├── logs/                   # Directorio para los archivos de log (generado automáticamente).
│   ├── access.log
│   └── error.log
│
├── index.js                # Punto de entrada principal que exporta el middleware.
├── sanitizer.js            # Lógica para la sanitización de datos de entrada.
├── xssSanitizer.js         # Middleware para la prevención de ataques XSS.
├── requestLimit.js         # Middleware para la limitación de peticiones.
├── logger.js               # Configuración del sistema de logging.
├── jest.config.js          # Configuración del entorno de pruebas Jest.
├── package.json            # Dependencias y scripts del proyecto.
└── .gitignore              # Archivos y carpetas ignorados por Git.
```

---

## Tecnologías y Dependencias

Este proyecto está construido con **Node.js** y utiliza las siguientes dependencias principales:

-   **express**: Framework web para Node.js.
-   **helmet**: Middleware para configurar cabeceras HTTP seguras.
-   **express-rate-limit**: Middleware para limitar peticiones repetidas a la API.
-   **xss-clean**: Middleware para sanitizar el cuerpo, los parámetros y las queries de las petricas contra ataques XSS.
-   **express-mongo-sanitize**: Middleware para sanitizar datos contra inyección de operadores NoSQL.
-   **winston**: Librería para un logging versátil y configurable.
-   **dotenv**: Módulo para cargar variables de entorno desde un archivo `.env`.

---

## Instalación

1.  Para agregar el paquete a tu proyecto, ejecuta el siguiente comando en tu terminal:

    ```bash
    npm install mbcj-secure
    ```

2.  Crea un archivo `.env` en la raíz de tu proyecto para configurar las variables de entorno. A continuación se muestra un ejemplo completo con todas las opciones disponibles.

    ```env
    # --- Configuración General (Sugerida) ---
    PORT=5000
    DEVELOP=false

    # --- Rutas (Ajustar según tu proyecto) ---
    # Ruta absoluta al directorio donde se guardarán los logs
    PATH_LOGS="/ruta/a/tu/proyecto/logs"
    # Ruta absoluta al archivo JSON para IPs baneadas permanentemente
    PATH_BAN="/ruta/a/tu/proyecto/permanent-ban.json"

    # --- Ralentización (Advertencia Suave) ---
    # En una ventana de 1 minuto...
    SLOW_TIME_MIN=1
    # ...empezar a ralentizar después de 20 peticiones.
    SLOW_REQUEST=20
    # ...añadiendo 100ms de retraso por cada petición extra.
    SLOW_DELAY=100

    # --- Bloqueo (Medida Fuerte) ---
    # En una ventana de 5 minutos...
    BAN_TIME_MIN=5
    # ...bloquear al usuario si supera las 50 peticiones.
    BAN_REQUEST=50
    # ...y la duración del bloqueo será de 10 minutos.
    BAN_TIMEOUT=10
    ```
    **Importante**: Asegúrate de que las rutas `PATH_LOGS` y `PATH_BAN` sean absolutas y apunten a directorios y archivos con los permisos de escritura necesarios.

---

## Uso

Para integrar el paquete, importa la función `secureControl` y pásale la instancia de tu aplicación de Express junto con un objeto de configuración.

A continuación, se muestra un ejemplo de implementación:

```javascript
// server.js

const express = require('express');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

// Importa la función de control desde el paquete
const { secureControl } = require('mbcj-secure');

const { PORT, DEVELOP, PATH_LOGS, PATH_BAN } = process.env;

const app = express();

// Llama a secureControl para que configure la seguridad en la app
secureControl(app, {
  logsPath: PATH_LOGS,
  banFilePath: PATH_BAN,
  isDevMode: DEVELOP === 'true' // Asegurarse de que sea booleano
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
```
