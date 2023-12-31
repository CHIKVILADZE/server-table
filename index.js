const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

const con = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

app.get('/', (req, res) => {
  con.query(
    'SELECT id, name, email, password, last_login, registration_time, status FROM blkbktcbas6ppjs2ez1x.userlist',
    (err, result) => {
      if (err) {
        console.error(err);
        res
          .status(500)
          .send({ message: 'An error occurred while fetching users' });
      } else {
        res.send(result);
      }
    }
  );
});

app.post('/register', (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const registration_time = req.body.registration_time;
  const status = req.body.status;

  con.query(
    'SELECT * FROM blkbktcbas6ppjs2ez1x.userlist WHERE email = ?',
    [email],
    (err, existingUser) => {
      if (err) {
        console.error('Error during registration:', err);
        res
          .status(500)
          .send({ message: '1 An error occurred during registration' });
      } else {
        if (existingUser.length > 0) {
          res.status(200).send({ message: 'User already exists' });
        } else {
          bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
            if (hashErr) {
              console.error('Error during password  hashing:', hashErr);
              res.status(500).send({
                message: '2 An error occurred  during registration',
              });
            } else {
              con.query(
                'INSERT INTO blkbktcbas6ppjs2ez1x.userlist( name, email, password, registration_time) VALUES( ?, ?, ?, ?)',
                [name, email, hashedPassword, registration_time, status],
                (insertErr, result) => {
                  if (insertErr) {
                    console.error('Error during registration:', insertErr);
                    res.status(500).send({
                      message: 'An error occurred during registration',
                      errorDetails: insertErr,
                    });
                  } else {
                    res.send(result);
                  }
                }
              );
            }
          });
        }
      }
    }
  );
});

const verifyJWT = (req, res, next) => {
  const token = req.headers['x-access-token'];

  if (!token) {
    res.send('You have no token');
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: 'You failed' });
      } else {
        req.userId = decoded.id;
        next();
      }
    });
  }
};

app.get('/isUserAuth', verifyJWT, (req, res) => {
  res.send('Heey you are authenticated Congratss');
});

app.post('/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  con.query(
    'SELECT * FROM blkbktcbas6ppjs2ez1x.userlist WHERE email = ?',
    [email],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send({ message: 'An error occurred during login' });
      } else {
        if (result.length > 0) {
          const hashedPassword = result[0].password;

          bcrypt.compare(password, hashedPassword, (compareErr, isMatch) => {
            if (compareErr) {
              console.error(compareErr);
              res
                .status(500)
                .send({ message: 'An error occurred during login' });
            } else if (isMatch) {
              const id = result[0].id;
              const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                expiresIn: 300,
              });

              if (result[0].status === 'active') {
                con.query(
                  'UPDATE blkbktcbas6ppjs2ez1x.userlist SET last_login = NOW() WHERE id = ?',
                  [result[0].id],
                  (err, updateResult) => {
                    if (err) {
                      console.error(err);
                      res.json({
                        auth: false,
                        message: 'An error occurred during login',
                      });
                    } else {
                      res.json({ auth: true, token, result });
                    }
                  }
                );
              } else if (result[0].status === 'blocked') {
                res.json({ auth: false, message: 'User is blocked' });
              }
            } else {
              res.json({ auth: false, message: 'Wrong email/password' });
            }
          });
        } else {
          res.json({ auth: false, message: 'Wrong email/password' });
        }
      }
    }
  );
});

app.put('/block-users', (req, res) => {
  const userIds = req.body.userIds;

  con.query(
    'UPDATE blkbktcbas6ppjs2ez1x.userlist SET status = ? WHERE id IN (?) AND status = ?',
    ['blocked', userIds, 'active'],
    (err, result) => {
      if (err) {
        console.error(err);
        res
          .status(500)
          .send({ message: 'An error occurred while blocking users' });
      } else {
        res.send({ message: 'Users blocked successfully' });
      }
    }
  );
});

app.put('/unblock-users', (req, res) => {
  const userIds = req.body.userIds;

  con.query(
    'UPDATE blkbktcbas6ppjs2ez1x.userlist SET status = ? WHERE id IN (?) AND status = ?',
    ['active', userIds, 'blocked'],
    (err, result) => {
      if (err) {
        console.error(err);
        res
          .status(500)
          .send({ message: 'An error occurred while blocking users' });
      } else {
        res.send({ message: 'Users unblocked successfully' });
      }
    }
  );
});

app.delete('/users/:id', (req, res) => {
  const userId = req.params.id;
  con.query(
    'DELETE FROM blkbktcbas6ppjs2ez1x.userlist WHERE id = ?',
    [userId],
    (err, result) => {
      if (err) {
        console.error(err);
        res
          .status(500)
          .send({ message: 'An error occurred while deleting the user' });
      } else {
        res.send(result);
      }
    }
  );
});

app.listen(8081, () => {
  console.log('Server is running on port 8081');
});
