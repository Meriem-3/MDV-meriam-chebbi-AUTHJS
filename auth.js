const express = require('express');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const db = require('./db');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const JWT_SECRET = 'ma_cle_super_secrete'; // ⚠️ à sécuriser dans un .env en prod

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Configurer EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ========== ROUTES ==========

// Page d'inscription
app.get('/signup', (req, res) => {
  res.render('signup');
});

// Traitement inscription
app.post('/signup', (req, res) => {
  const { username, password, role } = req.body;

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Erreur de hashage :', err);
      return res.status(500).json({ error: 'Erreur de hashage' });
    }

    const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    db.query(query, [username, hashedPassword, role], (err) => {
      if (err) {
        console.error('Erreur lors de l\'insertion MySQL :', err);
        return res.status(500).json({ error: 'Erreur lors de l\'enregistrement' });
      }
      res.redirect('/signin');
    });
  });
});

// Page de connexion
app.get('/signin', (req, res) => {
  res.render('signin');
});

// Traitement connexion
app.post('/signin', (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, result) => {
    if (err || result.length === 0) {
      console.error('Utilisateur non trouvé');
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const user = result[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error('Erreur comparaison :', err);
        return res.status(500).json({ error: 'Erreur lors de la vérification' });
      }

      if (!isMatch) {
        return res.status(401).json({ error: 'Mot de passe incorrect' });
      }

      // Générer le token JWT
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, {
        expiresIn: '1h',
      });

      res.status(200).json({ message: 'Connexion réussie', token });
    });
  });
});

// Page d’accueil simple
app.get('/', (req, res) => {
  res.send('Bienvenue sur le serveur d\'authentification !');
});

// Lancement du serveur
app.listen(3000, () => {
  console.log('Serveur démarré sur http://localhost:3000');
});
