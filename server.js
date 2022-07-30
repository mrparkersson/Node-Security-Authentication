const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const cookieSession = require('cookie-session');
const { Strategy } = require('passport-google-oauth20');

require('dotenv').config();

const app = express();

const PORT = 3000;

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  scope: ['email'],
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google profile', profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//Read the session from the cookie
passport.deserializeUser((id, done) => {
  //whatever it coming from our cookie is what's being populated in our req.uer(obj) in express
  done(null, id);
});

//checks our headers
app.use(helmet());
app.use(
  cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2],
  })
);
app.use(passport.initialize());
//authenticates our session
app.use(passport.session());

//middleware to check if the user is logged in or not before redirecting them to another page
function checkLoggedIn(req, res, next) {
  console.log('Current user is:', req.user);
  //check whether a user is logged in or not

  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'Please log in to get access',
    });
  }
  next();
}

//get google auth
app.get('/auth/google', passport.authenticate('google', { scope: ['email'] }));

//google callback based on OAuth
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    sessions: true,
  }),
  (req, res) => {
    res.send('Google called us back');
  }
);

//logout
app.get('/auth/logout', (req, res) => {
  //removes req.user and clears or terminate any logged in sessions
  req.logOut();
  //after logging out, redirect the user to the root
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('Your secret code is 4');
});

app.get('/failure', (req, res) => {
  return res.send('Failed to log in!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
};
app.listen(PORT, () => {
  console.log(`Server running on port: ${PORT}...`);
});
