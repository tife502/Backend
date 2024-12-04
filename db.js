require('dotenv').config();
const { Client } = require('pg');

const client = new Client({
    user: process.env.PGUSER,          // Reemplaza con tu nombre de usuario de PostgreSQL
    host: "localhost",
    database: "joyeria_db",      // Nombre de tu base de datos
    password: process.env.PGPASSWORD,    // Reemplaza con tu contraseña
    port: 5432,                   // Puerto por defecto de PostgreSQL
});

client.connect()
    .then(() => console.log('Conectado a la base de datos'))
    .catch(err => console.error('Error de conexión', err.stack));

module.exports = {client};  // Exporta el cliente para usar en otras partes de tu aplicación


