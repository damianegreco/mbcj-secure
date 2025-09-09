// __tests__/3-requestLimit.test.js
const express = require('express');
const request = require('supertest');
const http = require('http'); // Necesario para el test de Path Traversal

// NOTA: Ya no se necesitan variables de entorno para esta prueba.
// La configuración se pasa directamente a `secureControl`.

describe('Pruebas de Límite de Peticiones (Rate Limit & Slow Down)', () => {
  let app;
  let server;

  // Se usa `beforeEach` para asegurar que cada test tenga una instancia limpia de la app.
  beforeEach((done) => {
    jest.resetModules();
    app = express();
    
    // Se importa `secureControl` después de resetear los módulos.
    const { secureControl } = require('../index');

    // MODIFICADO: Se define un objeto de configuración para los tests.
    // Usamos valores bajos para que las pruebas se ejecuten rápidamente.
    const testSecurityOptions = {
      isDevMode: false,
      // Para el test de ralentización
      SLOW_TIME_MIN: 0.1, // 6 segundos
      SLOW_REQUEST: 5,    // Ralentiza a partir de la 6ta petición
      SLOW_DELAY: 100,    // Añade 100ms de retraso
      // Para el test de bloqueo
      BAN_TIME_MIN: 0.1,  // 6 segundos
      BAN_REQUEST: 10     // Bloquea a partir de la 11va petición
    };

    // MODIFICADO: Se pasa el objeto de opciones directamente a secureControl.
    secureControl(app, testSecurityOptions);

    // Rutas de prueba
    app.get('/', (req, res) => res.status(200).send('OK'));
    app.get('/secret', (req, res) => res.status(200).send('Secret Data'));

    // Se inicia el servidor para las pruebas de supertest
    server = app.listen(done);
  });

  // `afterEach` cierra el servidor para limpiar después de cada test.
  afterEach((done) => {
    server.close(done);
  });

  test('Debe permitir peticiones por debajo del límite', async () => {
    const response = await request(server).get('/');
    expect(response.status).toBe(200);
  });

  test('Debe ralentizar las peticiones por encima del límite de "slowDown"', async () => {
    // Se hacen 5 peticiones para llegar al límite de SLOW_REQUEST
    for (let i = 0; i < 5; i++) {
      await request(server).get('/');
    }
    
    // La 6ta petición debe ser ralentizada
    const startTime = Date.now();
    await request(server).get('/');
    const responseTime = Date.now() - startTime;
    
    // Verificamos que el tiempo de respuesta sea al menos el del delay
    expect(responseTime).toBeGreaterThanOrEqual(100);
  }, 10000); // Se aumenta el timeout de Jest por si acaso

  test('Debe bloquear las peticiones por encima del límite de "rateLimit"', async () => {
    // Se hacen 10 peticiones en paralelo para llegar al límite de BAN_REQUEST
    const requests = Array(10).fill(0).map(() => request(server).get('/'));
    await Promise.all(requests);
    
    // La 11va petición debe ser bloqueada
    const response = await request(server).get('/');
    expect(response.status).toBe(429);
    expect(response.body.message).toMatch(/Demasiadas solicitudes/);
  }, 10000);

  test('Debe bloquear por Path Traversal con código 403', (done) => {
    // Se usa el módulo http nativo porque supertest normaliza las URLs,
    // lo que impediría probar el path traversal `../`
    const options = {
      hostname: '127.0.0.1',
      port: server.address().port,
      path: '/some/path/../../secret', // Intento de ataque
      method: 'GET'
    };

    const req = http.request(options, (res) => {
      expect(res.statusCode).toBe(403);
      done();
    });

    req.on('error', (e) => {
      done(e); // Falla el test si hay un error
    });

    req.end();
  });
});