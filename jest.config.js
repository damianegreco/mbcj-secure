module.exports = {
  testMatch: ['**/__tests__/**/*.test.js'],

  // Habilitamos la recolección de cobertura para que se genere el JSON
  collectCoverage: true,

  // Definimos dónde se guardarán TODOS los reportes de cobertura
  coverageDirectory: 'test-report/coverage',

  // Formatos de los reportes de cobertura (AQUÍ ESTÁ TU JSON)
  coverageReporters: ['json-summary', 'lcov', 'text'],

  // Reporters para la salida de los tests (consola y XML)
  reporters: [
    'default',
    [
      'jest-html-reporters',
      {
        publicPath: './test-report',
        filename: 'report.html',
        expand: true,
      },
    ],
    [
      'jest-junit', // El nuevo reporter XML
      {
        // CORRECCIÓN: Le decimos explícitamente dónde guardar el archivo
        outputDirectory: './test-report',
        outputName: 'junit.xml',
      },
    ],
  ],
};