module.exports = function(app, passport) {

  app.get('/', function(req, res) {
    res.render('index.ejs');
  });

  app.get('/login', function(req, res) {
    res.render('login.ejs', {
      message: req.flash('loginMessage'),
      action: "Login",
      alternative: "Signup",
      text: "Need an account?"
    });
  });

  // process the login form
  // app.post('/login', do all our passport stuff here);

  app.get('/signup', function(req, res) {
    res.render('signup.ejs', {
      message: req.flash('signupMessage'),
      action: "Signup",
      alternative: "Login",
      text: "Already have an account?"
    });
  });

  // process the signup form
  // app.post('/signup', do all our passport stuff here);

  app.get('/profile', isLoggedIn, function(req, res) {
    res.render('profile.ejs', {
      user : req.user // get the user out of session and pass to template
    });
  });

  app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
  });
};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
        return next();
    res.redirect('/');
}
