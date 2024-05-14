const express = require('express');
require('dotenv').config();

const bodyParser = require('body-parser');
const app = express();
const accountRoutes = require('./routes/account');

app.use(bodyParser.json());
require('./database');

app.use('/api', accountRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});


