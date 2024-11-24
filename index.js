const express = require('express');
const routes = require('./routes'); // Importa el archivo de rutas
const { client } = require('./db'); // Importa la conexión a la base de datos

const app = express();
app.use(express.json());
app.use(routes); // Usa las rutas importadas

const PORT = process.env.PORT ;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
