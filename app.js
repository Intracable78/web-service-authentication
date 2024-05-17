const express = require('express');
require('dotenv').config();

const bodyParser = require('body-parser');
const app = express();
const accountRoutes = require('./routes/account');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
require('./database');
app.use(bodyParser.json());

app.use('/api', accountRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const swaggerOptions = {
    swaggerDefinition: {
      openapi: '3.0.0',
      info: {
        title: 'API Documentation authentification',
        version: '1.0.0',
      },
      servers: [
        {
          url: 'http://localhost:3000/api/',
          description: 'Serveur de test authentification'
        },
      ],
      components: {
        securitySchemes: {
          BearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          }
        }
      },
      security: [
        {
          BearerAuth: []
        }
      ]
    },
    apis: ['./routes/*.js'],
  };

  const swaggerDocs = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));


