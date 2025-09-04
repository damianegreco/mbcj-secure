// __tests__/2-sanitizers.test.js
const express = require('express');
const request = require('supertest');
const { secureControl } = require('../index');

describe('Pruebas de Sanitizadores (NoSQL & XSS)', () => {
  let app;

  beforeEach(() => {
    app = express();
    secureControl(app, { isDevMode: false });
    app.post('/data', (req, res) => res.status(200).json(req.body));
    app.get('/data', (req, res) => res.status(200).json(req.query));
  });

  test('Debe eliminar claves que empiezan con "$" del req.body', async () => {
    const maliciousPayload = { username: 'user', '$gt': '' };
    const response = await request(app).post('/data').send(maliciousPayload);
    expect(response.body).toEqual({ username: 'user' });
  });

  test('Debe eliminar claves que contienen "$" del req.query', async () => {
    const response = await request(app).get('/data?role=admin&password[$ne]=null');
    expect(response.body).toEqual({ role: 'admin' });
  });

  test('Debe limpiar scripts de XSS del req.body', async () => {
    const payload = { comment: '<script>alert("XSS")</script>', message: 'Mensaje limpio' };
    const response = await request(app).post('/data').send(payload);
    expect(response.body.comment).toBe('');
    expect(response.body.message).toBe('Mensaje limpio');
  });

  test('Debe limpiar scripts de XSS del req.query', async () => {
    const response = await request(app).get('/data?search=<img src=x onerror=alert(1)>');
    expect(response.body.search).toBe('');
  });
});