const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

interface User {
  userId: number;
  username: string;
  userIsAdmin: 1 | 0;
}

//For env File 
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8000;

app.post('/register', async function (req: any, res: any) {
  try {
    const { password, username, userIsAdmin } = req.body;

    const isAdmin = userIsAdmin ? 1 : 0

    const hashedPassword = await bcrypt.hash(password, 10);

    const [user] = await req.db.query(
      `INSERT INTO user (user_name, password, admin_flag)
      VALUES (:username, :hashedPassword, :userIsAdmin);`,
      { username, hashedPassword, userIsAdmin: isAdmin });
    
    const payload: User = {
       userId: user.insertId, 
       username, 
       userIsAdmin: isAdmin
    }
  
    const jwtEncodedUser = jwt.sign(
      payload,
      process.env.JWT_KEY
    );

    res.json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    console.log('error', err);
    res.json({ err, success: false });
  }
});

app.post('/log-in', async function (req: any, res: any) {
  try {
    const { username, password: userEnteredPassword } = req.body;

    const [[user]] = await req.db.query(`SELECT * FROM user WHERE user_name = :username`, { username });

    if (!user) res.json('Username not found');
  
    const hashedPassword = `${user.password}`
    const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);

    if (passwordMatches) {
      const payload: User = {
        userId: user.id,
        username: user.username,
        userIsAdmin: user.admin_flag
      }
      
      const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);

      res.json({ jwt: jwtEncodedUser, success: true });
    } else {
      res.json({ err: 'Password is wrong', success: false });
    }
  } catch (err) {
    console.log('Error in /authenticate', err);
  }
});

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
app.use(async function verifyJwt(req: any, res: any, next: any) {
  const { authorization: authHeader } = req.headers;
  
  if (!authHeader) res.json('Invalid authorization, no authorization headers');

  const [scheme, jwtToken] = authHeader.split(' ');

  if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');

  try {
    const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);

    req.user = decodedJwtObject;
  } catch (err: any) {
    console.log(err);
    if (
      err.message && 
      (err.message.toUpperCase() === 'INVALID TOKEN' || 
      err.message.toUpperCase() === 'JWT EXPIRED')
    ) {

      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);
    } else {

      throw((err.status || 500), err.message);
    }
  }

  await next();
});

app.post('/car', async (req: any, res: any) => {
  const { 
    newMakeValue,
    newModelValue,
    newYearValue
  } = req.body;

  const { userId } = req.user;

  const [insert] = await req.db.query(`
    INSERT INTO car (make, model, year, date_created, user_id, deleted_flag)
    VALUES (:newMakeValue, :newModelValue, :newYearValue, NOW(), :user_id, :deleted_flag);
  `, { 
    newMakeValue, 
    newModelValue,
    newYearValue,
    user_id: userId, 
    deleted_flag: 0
  });

  // Attaches JSON content to the response
  res.json({
    id: insert.insertId,
    newMakeValue,
    newModelValue,
    newYearValue,
    userId
   });
});

app.listen(port, () => {
  console.log(`Server is Fire at http://localhost:${port}`);
});
