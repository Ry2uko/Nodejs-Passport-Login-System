if(process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const mongoose = require('mongoose');

const initializePassport = require('./passport-config');
const User = require('./models/user');

const app = express();

const users = [];

initializePassport(passport);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.use('/css', express.static(__dirname + '/node_modules/bootstrap/dist/css'));

mongoose.connect(process.env.DATABASE_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', err => console.error(err));
db.once('open', () => {
  console.log('Connected to Database');
});

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', {message: req.user.email});
});

// Login

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

// Register

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', 
  checkNotAuthenticated, 
  checkUserExists, 
  async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      email: req.body.email,
      password: hashedPassword
    });

    try {
      await user.save();
      res.redirect('/login');
    } catch {
      res.redirect('/register');
    }
  });

// Logout

app.delete('/logout', (req, res) => {
  req.logOut();
  res.redirect('/login');
});


function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

async function checkUserExists(req, res, next) {
  const user = await User.findOne({ email: req.body.email });
  
  if (user == null) {
    return next();
  }

  res.redirect('/register');
}

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
