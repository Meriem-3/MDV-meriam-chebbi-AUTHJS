const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const dotenv = require('dotenv');
dotenv.config();

const router = express.Router();

// Signup
router.post('/signup', (req, res) => {
  const { username, password, role } = req.body;

  bcrypt.hash(password, 10, (err, hashed) => {
    if (err) return res.status(500).json({ error: 'Erreur de hashage' });

    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    db.query(sql, [username, hashed, role], (err) => {
      if (err) return res.status(500).json({ error: 'Erreur lors de l\'enregistrement' });
      res.status(201).json({ message: 'Utilisateur enregistré' });
    });
  });
});

// Signin
router.post('/signin', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });

    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (!match) return res.status(401).json({ error: 'Mot de passe incorrect' });

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
      );

      res.json({ message: 'Connexion réussie', token });
    });
  });
});

module.exports = router;
