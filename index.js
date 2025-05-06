require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');

const expireTime = 1000 * 60 * 60; // 1 hour

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = require('./database.js');

const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

app.set('view engine', 'ejs');

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
        res.render('homeLogged', {username: req.session.username});
    } else {
        res.render('homeUnLogged');
    }
})

app.get('/signup', (req,res) => {
    res.render("signup");
});

app.get('/login', (req,res) => {
    res.render("login");
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.post('/createUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
  
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validation = schema.validate(req.body);
    if(validation.error != null) {
        res.render('sqlInjection');
        return;
    }

    const result = await userCollection.find({email: email}).toArray();

    if(result.length != 0) {
        res.render('duplicateUserError');
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: 'user'});

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    return res.redirect('/members');
});

app.post('/loggingin', async (req,res) => {

    //initialize admin type for the my user
    await userCollection.updateOne({username: 'taylorhillier'}, {$set: {user_type: 'admin'}});

    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validation = schema.validate(req.body);
    if(validation.error != null) {
        res.render('sqlInjection');
        return;
    }
    
    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();

    if(result.length != 1 ) {
        res.redirect('/signup');
        return;
    }

    let username = result[0].username;

    if(await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.render('passwordError');
        return;
    }
});

app.get('/members', (req,res) => {
    let random = Math.ceil((Math.random()) * 3);

    if(req.session.authenticated) {
        res.render('members', {username: req.session.username, image: random});
    } else {
        res.redirect('/');
    }
}
);

app.get('/admin', async (req,res) => {

    const users = await userCollection.find({}).toArray();

    const userType = await userCollection.find({username: req.session.username}).project({user_type: 1}).toArray();
    if(userType[0].user_type != 'admin') {
        res.render('notAdminError');
        return;
    }
    if(userType.length == 0) {
        res.render('noUsersError');
        return;
    }

    res.render('admin', { users });
});

app.post('/promoteUser', async (req,res) => {
    const username = req.body.username;
    await userCollection.updateOne({username: username}, {$set: {user_type: 'admin'}});
    res.redirect('/admin');
});

app.post('/demoteUser', async (req,res) => {
    const username = req.body.username;
    await userCollection.updateOne({username: username}, {$set: {user_type: 'user'}});
    res.redirect('/admin');
});

app.use((req,res) => {
    res.status(404).send('404 Not Found!');
});

app.listen(port, () => {
    
    console.log(`Server is running on port ${port}`);
});