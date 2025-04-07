const express = require('express');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

router.get('/etudiant', authenticateToken, authorizeRoles('etudiant'), (req, res) => {
  res.send('Bienvenue étudiant');
});

router.get('/intervenant', authenticateToken, authorizeRoles('intervenant'), (req, res) => {
  res.send('Bienvenue intervenant');
});

router.get('/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.send('Bienvenue administrateur');
});

module.exports = router;
