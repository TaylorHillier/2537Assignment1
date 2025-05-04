require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');

const expireTime = 1000 * 60 * 60 * 24; 

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = require('./database.js');

const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.static('public'));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/sessions`,
    crypto: {
        secret: process.env.MONGODB_SESSION_SECRET
    },
});

app.use(session({
    secret: node_session_secret,
    resave: true,
    saveUninitialized: false,
    store: mongoStore,
}))

app.get('/', (req,res) => {
    if(req.session.username) {
        res.send(`<h1> Hello ${req.session.username}!</h1><br><a href='/members'>Go to members section'</a><br><a href='/logout'>Logout</a>
            `);
    } else {
        res.send("<br><a href='/signup'>Sign up</a><br><a href='/login'>Login</a><br>");
    }
    
})

app.get('/signup', (req,res) => {
    res.send(
        `<form action='/createUser' method='POST'>
         <input type='text' name='username' placeholder='Enter a user name' required>
            <input type='email' name='email' placeholder='Enter your email' required>
             <input type='password' name='password' placeholder='Enter a Password' required>
            <input type='submit' value='Submit'>
        </form>`
    )
});

app.get('/login', (req,res) => {
    res.send(
        `<form action='/loggingin' method='POST'>
            <input type='email' name='email' placeholder='Enter your email' required>
            <input type='password' name='password' placeholder='Enter a Password' required>
            <input type='submit' value='Submit'>
        </form>`
    )
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.post('/createUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
  

    const schema = Joi.string().max(20).required();
    const validation = schema.validate(email);
    if(validation.error != null) {
        res.send('Invalid username! SQL injection detected!');
        res.redirect('/signup');
        return;
    }

    const result = await userCollection.find({email: email}).toArray();

    if(result.length != 0) {
        res.send('User already exists!');
        res.redirect('/signup');
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({username: username, email: email, password: hashedPassword});

    res.send('User created successfully!<br><a href="/login">Login</a>');
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validation = schema.validate(email);
    if(validation.error != null) {
        res.send('Invalid username! SQL injection detected!');
        return;
    }

    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();

 
    if(result.length != 1 || username == null) {
        res.redirect('/signup');
        return;
    }

    let username = result[0].username || null;

    if(await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.send('Invalid password!');
        res.redirect('/login');
        return;
    }
});

app.get('/members', (req,res) => {
    let random = Math.ceil((Math.random()) * 3);

    if(req.session.authenticated) {
        console.log("image" + random);
        res.send(`<h1> Hello ${req.session.username}!</h1><br>
            <br><img src="/image${random}.png" width='300px' height='200px'><br>
            <a href='/logout'>Logout</a>`);
    } else {
        res.redirect('/');
    }
}
);

app.use((req,res) => {
    res.status(404).send('404 Not Found!');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);

});