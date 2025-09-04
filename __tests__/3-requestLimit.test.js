// __tests__/3-requestLimit.test.js
const express = require('express');
const request = require('supertest');
const http = require('http'); // Necesario para el test de Path Traversal

// Mock de variables de entorno
process.env.SLOW_TIME_MIN = '1';
process.env.SLOW_REQUEST = '5';
process.env.SLOW_DELAY = '100';
process.env.BAN_TIME_MIN = '1';
process.env.BAN_REQUEST = '10';
process.env.BAN_TIMEOUT = '1';

describe('Pruebas de Límite de Peticiones (Rate Limit & Slow Down)', () => {
  let app;
  let secureControl;
  let server; // Variable para el servidor

  beforeEach((done) => {
    jest.resetModules();
    app = express();
    secureControl = require('../index').secureControl;
    secureControl(app, { isDevMode: false });
    app.get('/', (req, res) => res.status(200).send('OK'));
    app.get('/secret', (req, res) => res.status(200).send('Secret Data'));
    server = app.listen(done); // Inicia el servidor antes de cada test
  });

  afterEach((done) => {
    server.close(done); // Cierra el servidor después de cada test
  });

  test('Debe permitir peticiones por debajo del límite', async () => {
    const response = await request(server).get('/');
    expect(response.status).toBe(200);
  });

  test('Debe ralentizar las peticiones por encima del límite de "slowDown"', async () => {
    // CORRECCIÓN: Peticiones en serie para garantizar el orden
    for (let i = 0; i < 5; i++) {
      await request(server).get('/');
    }
    
    const startTime = Date.now();
    await request(server).get('/'); // La 6ta petición debe tener delay
    const responseTime = Date.now() - startTime;
    
    expect(responseTime).toBeGreaterThanOrEqual(100);
  }, 10000);

  test('Debe bloquear las peticiones por encima del límite de "rateLimit"', async () => {
    // Las peticiones en paralelo están bien aquí
    await Promise.all(Array(10).fill(0).map(() => request(server).get('/')));
    
    const response = await request(server).get('/');
    expect(response.status).toBe(429);
  }, 10000);

  test('Debe bloquear por Path Traversal con código 403', (done) => {
    // CORRECCIÓN: Usamos el módulo http nativo para enviar una petición cruda.
    const options = {
      hostname: '127.0.0.1',
      port: server.address().port,
      path: '/some/path/../../secret',
      method: 'GET'
    };

    const req = http.request(options, (res) => {
      expect(res.statusCode).toBe(403);
      done();
    });

    req.on('error', (e) => {
      done(e);
    });

    req.end();
  });
});