// JWKS Server Project 2
// Kathryn Sheahen
// CSCE 3550 001

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  // Create a new SQLite database
  this.db = new sqlite3.Database('totally_not_my_privateKeys.db', (err) => {
    if (err) {
        console.error("error opening database " + err.message); //error msg
    } else {
        console.log('Connected to the totally_not_my_privateKeys database.'); //debug
        // Create a new table if it does not exist
        this.db.run(
          `CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL )`, (err) => {

              if (err) {
                  console.error("error creating table " + err.message); //error msg
              }
              console.log('Table created'); //debug
            }
        )
    }
    
  });
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);

      // Insert the valid keys into the database
      this.db.run(
        `INSERT INTO keys (key, exp) VALUES (?, ?)`,
          [keyPair.kid, payload.exp], (err) => {
          if (err) {
              console.error("error inserting key " + err.message);
          }
          console.log(`Active Key inserted`); //debug 
        }
      )
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);

  
    // Insert expired keys into the database
    this.db.run(
        `INSERT INTO keys (key, exp) VALUES (?, ?)`,
          [keyPair.kid, payload.exp], (err) => {
          if (err) {
              console.error("error inserting key " + err.message);
          }
          console.log(`Expired Key inserted`); //debug
        }
      )
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

