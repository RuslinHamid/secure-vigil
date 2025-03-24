const express = require('express');
const app = express();
const fs = require('fs');
const { exec } = require('child_process');

app.use(express.json());

// XSS Vulnerability
app.get('/welcome', (req, res) => {
    const name = req.query.name;
    // Vulnerable XSS
    res.send(`<h1>Welcome ${name}!</h1>`);
});

// Prototype Pollution Vulnerability
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            // Vulnerable recursive merge
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Command Injection Vulnerability
app.get('/execute', (req, res) => {
    const cmd = req.query.cmd;
    // Vulnerable command execution
    exec(cmd, (error, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

// Insecure Direct Object References
app.get('/user/:id', (req, res) => {
    // Vulnerable IDOR
    const userData = fs.readFileSync(`/users/${req.params.id}.json`, 'utf8');
    res.json(JSON.parse(userData));
});

// Eval Injection Vulnerability
app.post('/calculate', (req, res) => {
    const { expression } = req.body;
    // Vulnerable eval usage
    const result = eval(expression);
    res.json({ result });
});

// NoSQL Injection Vulnerability
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Vulnerable NoSQL query
    db.users.find({
        username: username,
        password: password
    }).toArray((err, result) => {
        if (result.length > 0) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    });
});

// Insecure Random Values
function generateToken() {
    // Vulnerable random token generation
    return Math.random().toString(36).substring(7);
}

// Path Traversal Vulnerability
app.get('/download', (req, res) => {
    const filename = req.query.file;
    // Vulnerable file access
    fs.readFile(filename, (err, data) => {
        if (err) res.status(404).send('File not found');
        else res.send(data);
    });
});

// Hardcoded Credentials
const dbConfig = {
    username: 'admin',
    password: 'super_secret_123',
    host: 'localhost',
    port: 27017
};

// Insecure Cookie Settings
app.get('/login-success', (req, res) => {
    // Vulnerable cookie settings
    res.cookie('session', generateToken(), {
        httpOnly: false,
        secure: false
    });
    res.send('Logged in');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
}); 