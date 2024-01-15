const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const helmet = require('helmet')

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet())

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));


app.use(session({
  secret: 'Cornelius',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 45 * 60 * 1000, 
  },
}));


mongoose.connect('mongodb://localhost/cornelius', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  userId: mongoose.Schema.Types.ObjectId,
  timestamp: { type: Date, default: Date.now },
  signature: String,
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);

const isLoggedIn = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.userId = user.id;
    res.redirect('/home');
  } else {
    res.redirect('/login');
  }
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Kontrollera om användarnamnet redan finns i databasen
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      // Skicka med felmeddelandet till vyen och använd render-metoden
      return res.render('register', { error: 'Username is already taken' });
    }

    // Om användarnamnet inte finns, fortsätt med registreringen
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });

    await user.save();
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    // Skicka med felmeddelandet till vyen och använd render-metoden
    return res.render('register', { error: 'Internal Server Error' });
  }
});



app.get('/home', async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }

    const posts = await Post.find();
    res.render('home', { user, posts });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/newpost', isLoggedIn, (req, res) => {
  res.render('newpost');
});

app.post('/newpost', isLoggedIn, async (req, res) => {
  const { title, content } = req.body;
  const user = await User.findById(req.session.userId);

  const post = new Post({
    title,
    content,
    userId: req.session.userId,
    signature: user.username, // Signatur från inloggad användare
  });

  await post.save();
  res.redirect('/home');
});

app.post('/deletepost/:id', isLoggedIn, async (req, res) => {
  const postId = req.params.id;
  await Post.findByIdAndDelete(postId);
  res.redirect('/home');
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    } else {
      res.redirect('/login');
    }
  });
});

app.post('/deletepost/:id', isLoggedIn, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.session.userId;

    // Hitta det aktuella inlägget och kontrollera om det tillhör den inloggade användaren
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).send('Post not found');
    }

    if (!post.userId.equals(userId)) {
      return res.status(403).send('Unauthorized');
    }

    // Ta bort inlägget från databasen
    await Post.findByIdAndDelete(postId);
    res.redirect('/home');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


