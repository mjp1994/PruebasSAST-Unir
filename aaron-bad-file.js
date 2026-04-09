const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const AWS = require('aws-sdk');
const app = express();

// --- VULNERABILITY: HARDCODED SECRETS ---
// In a real scenario, actual AWS Access Keys would be placed here.
// Storing credentials directly in source code is a major security risk.
const aws_config = {
  accessKeyId: "REPLACED_WITH_DUMMY_KEY_FOR_TESTING",
  secretAccessKey: "REPLACED_WITH_DUMMY_SECRET_FOR_TESTING",
  region: "us-east-1"
};
const s3 = new AWS.S3(aws_config);

const db = new sqlite3.Database(':memory:');
app.use(express.json());

// --- VULNERABILITY: SQL INJECTION ---
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: Direct concatenation of user input into the SQL string.
  // This allows an attacker to manipulate the query logic.
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

  db.all(query, (err, rows) => {
    if (err) {
      res.status(500).send("Database error");
    } else {
      res.send("Request processed");
    }
  });
});

app.listen(3000);
