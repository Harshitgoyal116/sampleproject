// jshint esversion: 6

require('dotenv').config();
const express = require('express');
//const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const flash = require('express-flash');
const MongoStore = require('connect-mongo');
const session = require('express-session');
const passport = require('passport');
const LocalStartegy = require('passport-local').Strategy;

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

//Initializing flash and session
app.use(flash());

app.use(session({
  secret: process.env.COOKIE_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({mongoUrl: process.env.MONGO_URL}),
  cookie: {maxAge: 24 * 60 * 60 * 1000}
}));

//connecting to database
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  useCreateIndex: true
});


//creating table structure
const userSchema = new mongoose.Schema({
  Username: {type: String, unique: true},
  Name: String,
  Password: String,
});

//creating schema
const User = new mongoose.model("User", userSchema);

// Passport start
// Passport config
function init(passport){
  passport.use(new LocalStartegy({usernameField: "username", passwordField: "password"}, async (username, password, done)=>{
    // Login Logic
    // check if username exists
    const user = await User.findOne({Username: username});
    if(!user){
      return done(null, false, {message: "No user with this username is found!"});
    }
    bcrypt.compare(password, user.Password).then((match)=>{
      if(match){
        return done(null, user, {message: "Logged in successfully!"});
      }
      return done(null, false, {message: "Invalid Credential"});
    }).catch((err)=>{
      return done(null, false, {message: "Something went wrong!"});
    });
  }));

  // serialization and deserialization
  passport.serializeUser((user, done)=>{
    done(null, user._id);
  });

  passport.deserializeUser((id, done)=>{
    User.findById(id, (err, user)=>{
      done(err, user);
    });
  });
}

//calling passaport function
init(passport);
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next)=>{
  res.locals.session = req.session;
  res.locals.user = req.user;
  next();
});
// Passport End

//All routes
//rendering webpages
app.get('/', function(req, res){
  if(req.isAuthenticated()){
    return res. redirect('/home')
  }
  res.render("index", {currentPage: "index"});
});

app.post('/', (req, res, next)=>{
  // passport login logic
  passport.authenticate("local", function(err, user, info){
    if(err){
      req.flash("error", info.message);
      return next(err);
    }

    if(!user){
      req.flash("error", info.message);
      return res.redirect('/');
    }

    req.logIn(user, function(err){
      if(err){
        req.flash("error", info.message);
      }
      return res.redirect('/home');
    });
  })(req, res, next);
});

app.get('/home', function(req, res){
  if(req.isAuthenticated()){
    return res.render("home", {currentPage: "home"});
  }
  res.redirect('/');
});

app.get('/register', function(req, res){
  if(req.isAuthenticated()){
    return res.redirect('/home');
  }
  res.render("register", {currentPage: "register"});
})

app.post('/register', async function(req, res){
  const username = req.body.username;
  const name = req.body.name;
  const password = req.body.pass;
  const cpassword = req.body.cpass;
  const hash = await bcrypt.hash(password, 10);

  if (cpassword === password){
    User.exists({username: username}, function(err, foundUser){
      if (err){
        console.log(err);
      }
      if(foundUser){
        //res.send('Username already exists');
        req.flash('error', 'Username already exists');
        res.redirect('/register');
      }else{
        const user = new User({
          Username: username,
          Name: name,
          Password: hash
        });
        user.save(function(err){
          if(err){
            console.log(err);
          }
        })
        req.flash('success', 'You are registered');
        res.redirect('/');
      }
    });
  }else{
    //res.send('Password does not match');
    req.flash('error', 'Password do not match');
    res.redirect('register');
  }
});

app.get('/sign-out', (req, res)=>{
  req.logOut();
  res.redirect('/');
});

app.listen(3100, function(){
//starting server
  console.log("Server started at PORT 3100");
});
