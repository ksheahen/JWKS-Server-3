// JWKS Server Project 3
// Kathryn Sheahen
// CSCE 3550 001

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');
const uuid = require('uuid');

const app = express();
const port = 8080;
app.use(express.json()); //middleware

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
const AES_ALGORITHM = 'aes-256-cbc'; // couldn't get encrypt/decrypt to work

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  // Create a new SQLite database
  this.db = new sqlite3.Database('totally_not_my_privateKeys.db', (err) => {
    if (err) {
        console.error("error opening database " + err.message); //error msg
    } else {
        console.log('Connected to the totally_not_my_privateKeys database.'); //debug

        // Create keys table
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

        // Create users table
        this.db.run(
          `CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP )`, (err) => {
                
                if (err) {
                    console.error("error creating users table " + err.message); //error msg
                }
                console.log('UsersTable created'); //debug
             }
        )
        // Create auth table
        this.db.run(
          `CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id) )`, (err) => {
                
                if (err) {
                    console.error("error creating auth table " + err.message); //error msg
                }
                console.log('Auth created'); //debug
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
  // const encryptedKey = encryptKeys(keyPair.toPEM(true)); -> couldn't get this to work
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

// AUTH POST endpoint
app.post('/auth', (req, res) => {
  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }

  console.log(req.body); //debug


  // Get user_id from users table and put into auth_logs
  db.run (
    `SELECT users.id from users JOIN auth_logs
      ON (users.id = auth_logs.user_id)`, (err, row) => {
        if (err) {
          console.error("error selecting user_id " + err.message);
        }
        console.log(`user_id selected`); //debug
      }
  )

  // Insert auth log into auth_logs table - this isn't getting picked up by gradebot so idk whats wrong
  db.run (
    `INSERT INTO auth_logs (request_ip, request_timestamp) VALUES (?, ?)`,
    [req.ip, Date.now()], (err) => {
      if (err) {
        console.error("error inserting auth log " + err.message);
      }
      console.log(`auth log inserted`); //debug
      
    }
  )

  res.send(token);

});


app.all('/register', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
})

// REGISTER endpoint
app.post('/register', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
      const password = uuid.v4();
      const user = {
        username: req.body.username,
        email: req.body.email
      }

      console.log(password); //debug

      // Hash password
      const passwordHash = await argon2.hash(password);
      console.log(passwordHash); //debug

      // Insert user info into the users table
        db.run (
          `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
          [user.username, user.email, passwordHash], (err) => {
            if (err) {
              console.error("error inserting user info " + err.message);
              return res.status(500).json({message: "error inserting user"});
            }
              console.log(`user info inserted`); //debug
              return res.status(200).json({ message: 'User registered successfully', password});
            }
          
        )

 });


generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

