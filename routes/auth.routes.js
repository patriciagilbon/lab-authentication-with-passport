const express = require('express');
const router = express.Router();
const passport = require('passport')
const bcrypt = require('bcrypt')
const User = require('../models/User.model.js')
const Room = require('../models/Room.model.js')
const roundSalt = 10;

router.get('/signup', (req, res, next) =>{
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;
 
  // 1. Check username and password are not empty
  if (!username || !password) {
    res.render('auth/signup', { errorMessage: 'Indicate username and password' });
    return;
  }
 
  User.findOne({ username })
    .then(user => {
      // 2. Check user does not already exist
      if (user !== null) {
        res.render('auth/signup', { message: 'The username already exists' });
        return;
      }
 
      // Encrypt the password
      const salt = bcrypt.genSaltSync(roundSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new User({
        username,
        password: hashPass
      });
 
      newUser
        .save()
        .then(() => res.redirect('/'))
        .catch(err => next(err));
    })
    .catch(err => next(err));
});


router.get('/login', (req, res, next) =>{
  res.render('auth/login', { errorMessage: req.flash('error') });
})

router.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', failureMessage: 'true', failureFlash: true}),
  function(req, res) {
    res.redirect('/private');
  });

  router.get('/private', ensureAuthenticated, (req, res) => {
    res.render('auth/private', { user: req.user });
  });
   
  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      // The user is authenticated
      // and we have access to the logged user in req.user
      return next();
    } else {
      res.redirect('/login');
    }
  }
  router.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/login');
  });

  router.post('/rooms', ensureAuthenticated, (req, res, next) => {
    const { name, desc } = req.body;
    const { _id } = req.user; // <-- Id from the logged user
    Room.create({
      name,
      desc,
      owner: _id,
    })
      .then(() => res.redirect('/rooms'))
      .catch((err) => next(err));
  });

  router.get('/rooms', ensureAuthenticated, (req, res, next) => {
    const { _id } = req.user;
    Room.find({ owner: _id })
      .then((myRooms) => res.render('auth/rooms', { rooms: myRooms }))
      .catch((err) => next(err));
  });

  
module.exports = router;
