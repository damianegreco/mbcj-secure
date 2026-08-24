// __tests__/1-securityHeaders.test.js
const express = require('express');
const request = require('supertest');

describe('Pruebas de Cabeceras de Seguridad', () => {

  // Cada test es 100% independiente para evitar la fuga de estado (especialmente para CORS).
  // Para ello, se resetean los módulos y se crea una nueva 'app' dentro de cada bloque 'test'.

  test('Helmet debe establecer cabeceras de seguridad básicas', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    secureControl(app, { isDevMode: false });
    app.get('/', (req, res) => res.status(200).send('OK'));
    
    const response = await request(app).get('/');
    expect(response.headers['x-frame-options']).toBe('SAMEORIGIN');
  });

  test('HPP debe manejar la contaminación de parámetros', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    secureControl(app, { isDevMode: false });
    app.get('/search', (req, res) => res.status(200).json(req.query));
    
    const response = await request(app).get('/search?product=A&product=B');
    // CORRECCIÓN: 'B' debe ser un string entre comillas.
    expect(response.body.product).toEqual(['A', 'B']);
  });

  test('CORS debe permitir un origen configurado', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    const corsOptions = { origin: 'https://mi-frontend.com' };
    secureControl(app, { isDevMode: false, corsOptions });
    app.get('/', (req, res) => res.status(200).send('OK'));
    
    const response = await request(app).get('/').set('Origin', 'https://mi-frontend.com');
    expect(response.headers['access-control-allow-origin']).toBe('https://mi-frontend.com');
  });

  test('CORS debe bloquear un origen no permitido', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    const corsOptions = { origin: 'https://mi-frontend.com' };
    secureControl(app, { isDevMode: false, corsOptions });
    app.get('/', (req, res) => res.status(200).send('OK'));

    const response = await request(app).get('/').set('Origin', 'https://sitio-malicioso.com');
    // Al ser bloqueado por CORS, esta cabecera no debe existir.
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });
  // --- CSP de WebAssembly acotada por ruta ---
  // Compilar WASM exige 'wasm-unsafe-eval' en script-src. Se habilita solo en las
  // rutas declaradas para no ampliar la superficie de ataque del resto.

  const scriptSrcDe = (response) => (response.headers['content-security-policy'] || '')
    .split(';').map(d => d.trim()).find(d => d.startsWith('script-src ')) || '';

  test('Sin wasmPaths, script-src no habilita WebAssembly', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    secureControl(app, { isDevMode: false });
    app.get('/policia/inicio', (req, res) => res.status(200).send('OK'));

    const response = await request(app).get('/policia/inicio');
    expect(scriptSrcDe(response)).not.toContain("'wasm-unsafe-eval'");
  });

  test('Con wasmPaths, solo las rutas declaradas habilitan WebAssembly', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    secureControl(app, { isDevMode: false, wasmPaths: ['/policia'] });
    app.get('/policia/inicio', (req, res) => res.status(200).send('OK'));
    app.get('/entregas/inicio', (req, res) => res.status(200).send('OK'));

    const permitida = await request(app).get('/policia/inicio');
    expect(scriptSrcDe(permitida)).toContain("'wasm-unsafe-eval'");

    const ajena = await request(app).get('/entregas/inicio');
    expect(scriptSrcDe(ajena)).not.toContain("'wasm-unsafe-eval'");
  });

  test('La CSP de wasmPaths conserva el resto de las directivas', async () => {
    jest.resetModules();
    const { secureControl } = require('../index');
    const app = express();
    secureControl(app, { isDevMode: false, wasmPaths: ['/policia'] });
    app.get('/policia/inicio', (req, res) => res.status(200).send('OK'));

    const response = await request(app).get('/policia/inicio');
    const csp = response.headers['content-security-policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    // 'unsafe-eval' a secas habilitaria ademas el eval() de JavaScript.
    expect(csp).not.toContain("'unsafe-eval'");
  });
});
