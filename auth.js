const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const { client } = require('./db'); // Importa la conexión



// Función para crear un token JWT
const createToken = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '90d' } // Cambia la duración si es necesario
  );
};

// Registro de Usuario
const register = async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Encripta la contraseña
    const newUser = await User.create({ email, password: hashedPassword, role });

    const token = createToken(newUser);
    res.status(201).json({ token, user: { id: newUser.id, email: newUser.email, role: newUser.role } });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar usuario', error });
  }
};

// Inicio de Sesión
const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    // Consulta el usuario en la base de datos usando el username
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    // Verifica si el usuario existe
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Compara la contraseña ingresada con la almacenada en la base de datos
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // Genera un token de autenticación para el usuario
    const token = createToken(user);
    res.status(200).json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: 'Error al iniciar sesión 2334' });
  }
};

// Verificación del Token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ message: 'Token no proporcionado' });
  }

  const tokenValue = token.split(" ")[1]; // Extrae el token sin el 'Bearer'
  
  jwt.verify(tokenValue, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token no válido' });
    }

    req.user = decoded;
    next();
  });
};

module.exports = {
  register,
  login,
  verifyToken,
  createToken
};
