const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
app.use(express.static('version Viano'));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const config = {
  user: 'Arturo',
  password: '12345',
  server: 'localhost',
  database: 'IMA_CITE_DB',
  options: {
    encrypt: false,
    trustServerCertificate: true
  }
};

// Configurar Nodemailer (ajusta según tu correo y contraseña)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'arturito8901345@gmail.com', // tu correo aquí
    pass: 'dejt fkpr fgpb lsww'     // tu password o app password
  }
});

// RUTA para solicitar recuperación de contraseña (envía email)
app.post('/recuperar-password', async (req, res) => {
  const { correo } = req.body;

  if (!correo) {
    return res.status(400).json({ mensaje: 'El correo es requerido' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('correo', sql.NVarChar, correo)
      .query('SELECT Nombre, Correo FROM Usuarios WHERE Correo = @correo');

    if (result.recordset.length === 0) {
      return res.status(404).json({ mensaje: 'Correo no registrado' });
    }

    const usuario = result.recordset[0];

    // Generar token y fecha de expiración (ej. 1 hora)
    const token = crypto.randomBytes(20).toString('hex');
    const expiracion = new Date(Date.now() + 3600000); // 1 hora después

    // Guardar token y expiración en la base de datos
    await pool.request()
      .input('correo', sql.NVarChar, correo)
      .input('token', sql.NVarChar, token)
      .input('expira', sql.DateTime, expiracion)
      .query(`UPDATE Usuarios SET TokenReset = @token, ExpiraTokenReset = @expira WHERE Correo = @correo`);

    // Construir URL para resetear (ajusta a tu frontend)
    const urlReset = `http://localhost:3000/reset-password.html?token=${token}&correo=${encodeURIComponent(correo)}`;

    // Enviar email
    const mailOptions = {
      from: '"IMA.CITE Soporte" <arturito8901345@gmail.com>',
      to: correo,
      subject: 'Recuperación de contraseña IMA.CITE',
      html: `<p>Hola ${usuario.Nombre},</p>
             <p>Haz solicitado restablecer tu contraseña. Haz clic en el enlace para cambiarla:</p>
             <a href="${urlReset}">Restablecer contraseña</a>
             <p>Si no solicitaste este cambio, ignora este mensaje.</p>`
    };

    await transporter.sendMail(mailOptions);

    res.json({ mensaje: 'Correo enviado con instrucciones para recuperar la contraseña.' });
  } catch (error) {
    console.error('Error en /recuperar-password:', error);
    res.status(500).json({ mensaje: 'Error email' });
  }
});

// RUTA para resetear la contraseña con token válido
app.post('/reset-password', async (req, res) => {
  const { correo, token, nuevaContrasena } = req.body;

  if (!correo || !token || !nuevaContrasena) {
    return res.status(400).json({ mensaje: 'Faltan datos obligatorios' });
  }

  try {
    const pool = await sql.connect(config);

    // Buscar usuario con token válido y no expirado
    const result = await pool.request()
      .input('correo', sql.NVarChar, correo)
      .input('token', sql.NVarChar, token)
      .query(`SELECT TokenReset, ExpiraTokenReset FROM Usuarios 
              WHERE Correo = @correo AND TokenReset = @token`);

    if (result.recordset.length === 0) {
      return res.status(400).json({ mensaje: 'Token inválido o correo incorrecto' });
    }

    const usuario = result.recordset[0];
    if (!usuario.ExpiraTokenReset || new Date() > usuario.ExpiraTokenReset) {
      return res.status(400).json({ mensaje: 'El token ha expirado' });
    }

    // Hashear la nueva contraseña
    const saltRounds = 10;
    const hash = await bcrypt.hash(nuevaContrasena, saltRounds);

    // Actualizar la contraseña y limpiar token
    await pool.request()
      .input('correo', sql.NVarChar, correo)
      .input('hash', sql.NVarChar, hash)
      .query(`UPDATE Usuarios 
              SET Contraseña = @hash, TokenReset = NULL, ExpiraTokenReset = NULL 
              WHERE Correo = @correo`);

    res.json({ mensaje: 'Contraseña actualizada con éxito' });
  } catch (error) {
    console.error('Error en /reset-password:', error);
    res.status(500).json({ mensaje: 'Error hash' });
  }
});

// Ruta POST /registro
app.post('/registro', async (req, res) => {
  const { nombre, correo, contrasena, rol } = req.body;
  console.log('Datos recibidos:', { nombre, correo, contrasena, rol });

  if (!nombre || !correo || !contrasena || !rol) {
    return res.status(400).json({ mensaje: 'Faltan datos obligatorios' });
  }

  try {
    const pool = await sql.connect(config);
    console.log('Conexión a DB exitosa');

    const result = await pool.request()
      .input('correo', sql.NVarChar, correo)
      .query('SELECT COUNT(*) as count FROM Usuarios WHERE Correo = @correo');

    console.log('Resultado de consulta:', result.recordset);

    if (result.recordset[0].count > 0) {
      return res.status(400).json({ mensaje: 'El correo ya está registrado' });
    }
    //Encriptar
    const saltRounds = 10;
    const hash = await bcrypt.hash(contrasena, saltRounds);
    console.log('Hash generado:', hash);

    await pool.request()
      .input('nombre', sql.NVarChar, nombre)
      .input('correo', sql.NVarChar, correo)
      .input('contrasena', sql.NVarChar, hash)
      .input('rol', sql.NVarChar, rol)
      .query(`
        INSERT INTO Usuarios (Nombre, Correo, Contraseña, Rol) 
        VALUES (@nombre, @correo, @contrasena, @rol)
      `);

    res.json({ mensaje: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error en /registro:', error);
    res.status(500).json({ mensaje: 'Error' });
  }
});


// Ruta POST /login
app.post('/login', async (req, res) => {
  const { correo, contraseña } = req.body;

  if (!correo || !contraseña) {
    return res.status(400).json({ mensaje: 'Faltan datos obligatorios' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('correo', sql.VarChar, correo)
      .query(`SELECT Nombre, Correo, Rol, Estado, Contraseña FROM Usuarios WHERE Correo = @correo`);

    if (result.recordset.length === 0) {
      return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });
    }

    const usuario = result.recordset[0];

    if (!usuario.Estado) {
      return res.status(403).json({ mensaje: 'Cuenta inactiva. Contacta al administrador.' });
    }

    // Compara la contraseña ingresada con el hash almacenado
    const esValida = await bcrypt.compare(contraseña, usuario.Contraseña);

    if (!esValida) {
      return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });
    }

    res.json({
      mensaje: 'Inicio de sesión exitoso',
      nombre: usuario.Nombre,
      rol: usuario.Rol
    });

  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ mensaje: 'Error del servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
