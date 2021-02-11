require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {maxAge: 1000 * 60 * 60 * 24 * 7}
  })
);

massive({
  connectionString: CONNECTION_STRING,
  ssl: {rejectUnauthorized:false}
}).then(db => {
  app.set('db', db);
  console.log('db connected')
});

app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  let db = req.app.get('db');
  const user = await db.check_user_exists(email)
  if (user[0]){
    return res.status(401).send('User already exists');
  }
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);
  let [createdUser] = await db.create_user([email, hash])
  req.session.user = { id: createdUser.id, email: createdUser.email}
  res.status(200).send(req.session.user)
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  let db = req.app.get('db');
  let [foundUser] = await db.check_user_exists(email);
  if (!foundUser){
    return res.status(401).send('Incorrect credentials!');
  }
  let authenticated = bcrypt.compareSync(password, foundUser.user_password);
  if(authenticated){
    req.session.user = {
      id: foundUser.id,
      email: foundUser.email
    }
    res.status(200).send(req.session.user)
  } else {
    return res.status(401).send('Incorrect credentials!')
  }
})

app.get('/auth/logout', (req, user) => {
  req.session.destroy()
  res.sendStatus(200)
})

app.get('/auth/user', (req, res) => {
  if(req.session.user){
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('Please Log In')
  }
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});