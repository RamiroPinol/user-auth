const LocalStrategy = require('passport-local').Strategy;
const User = require('../user');

module.exports = (passport) => {

  passport.serializeUser( (user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser( (id, done) => {
    User.findById(id, (err, user) => {
      done(err, user);
    });
  });

  passport.use('local-signup', new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass back the entire request to the callback
  },
  (req, email, password, done) => {

    // asynchronous
    // User.findOne wont fire unless data is sent back
    process.nextTick( () => {

    // find a user whose email is the same as the forms email
    // we are checking to see if the user trying to login already exists
      User.findOne({ 'local.email' :  email }, (err, user) => {
        if (err)
          return done(err);

        // check to see if theres already a user with that email
        if (user) {
          return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
        } else {

          // if no user with that email, create new user
          const newUser = new User();
          newUser.local.email    = email;
          newUser.local.password = newUser.generateHash(password);

          newUser.save( (err) => {
            if (err) throw err;
            return done(null, newUser);
          });
        }
      });

    });

  }));
};
