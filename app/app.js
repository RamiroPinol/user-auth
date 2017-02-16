var express = require('express');
var app = express();
var reload = require('reload')
var mongoose = require('mongoose');
var passport = require('passport');
var flash = require('connect-flash');
var morgan = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');

var port = process.env.PORT || 4000;

var configDB = require('./lib/database');

mongoose.connect(configDB.url);

require('./lib/passport')(passport); // pass passport for configuration

app.use(morgan('dev')); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser()); // get information from html forms
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', 'app/views');

// required for passport
app.use(session({ secret: 'stop!youshouldnotreadthisbecauseisasecret' })); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

require('./routes.js')(app, passport); // load our routes and pass in our app and fully configured passport

var server = app.listen(port, () => {
  console.log('Listening on port ' + port);
});

reload(server, app);
