const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');

const app = express();

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());

// Логируем все входящие запросы
app.use((req, res, next) => {
  console.log(`Received ${req.method} request to ${req.url}`);
  next();
});

// Keycloak configuration
const keycloakRealm = 'reports-realm';
const keycloakUrl = 'http://keycloak:8080';
const issuerUrl = 'http://localhost:8080';
const jwksUri = `${keycloakUrl}/realms/${keycloakRealm}/protocol/openid-connect/certs`;

console.log(`JWKS URI: ${jwksUri}`);

const client = jwksClient({
  jwksUri: jwksUri,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      console.error('Error fetching signing key:', err);
      callback(err, null);
    } else {
      const signingKey = key?.getPublicKey();
      callback(null, signingKey);
    }
  });
}

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    console.log('No Authorization header provided for', req.url);
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    console.log('Invalid token format for', req.url);
    return res.status(401).json({ error: 'Invalid token format' });
  }

  console.log('Token for', req.url, ':', token);

  jwt.verify(token, getKey, {
    issuer: `${issuerUrl}/realms/${keycloakRealm}`,
    algorithms: ['RS256'],
  }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed for', req.url, ':', err.message);
      return res.status(401).json({ error: 'Token verification failed', details: err.message });
    }

    if (decoded.azp !== 'reports-frontend') {
      console.log('Invalid azp for', req.url, ':', decoded.azp);
      return res.status(401).json({ error: 'Invalid client', details: 'azp does not match reports-frontend' });
    }

    // Проверка роли report_user
    if (!decoded.realm_access?.roles.includes('report_user')) {
      console.log('User does not have required role for', req.url, ':', decoded.realm_access?.roles);
      return res.status(403).json({ error: 'Insufficient permissions', details: 'report_user role required' });
    }

    console.log('Decoded token for', req.url, ':', decoded);
    req.user = decoded;
    next();
  });
};

// Эндпоинт /reports с генерацией случайных данных
app.get('/reports', verifyToken, (req, res) => {
  const report = {
    id: Math.floor(Math.random() * 1000), // Случайный ID
    title: `Usage Report ${Math.floor(Math.random() * 100)}`,
    content: `This is a sample report generated on ${new Date().toISOString()}.`,
    user: req.user.preferred_username,
  };
  res.json(report);
});

// Эндпоинт /reports:1 (оставляем на случай, если запрос всё же появится)
app.get('/reports:1', verifyToken, (req, res) => {
  console.log('Received request for /reports:1');
  const report = {
    id: 1,
    title: "Usage Report 1",
    content: "This is a specific report for ID 1.",
    user: req.user.preferred_username,
  };
  res.json(report);
});

// Эндпоинт /reports/1 (оставляем на случай, если запрос будет исправлен)
app.get('/reports/1', verifyToken, (req, res) => {
  console.log('Received request for /reports/1');
  const report = {
    id: 1,
    title: "Usage Report 1",
    content: "This is a specific report for ID 1.",
    user: req.user.preferred_username,
  };
  res.json(report);
});

app.listen(8000, () => console.log('Backend running on port 8000'));