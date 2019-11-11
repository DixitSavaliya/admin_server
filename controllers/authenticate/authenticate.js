const jwt = require('jsonwebtoken');
const secret = "mysecretsshhh";

const withAuth = function (req, res, next) {
  const token = req.headers.token;
  if (!token) {
    res.status(401).send('Unauthorized: No token provided');
  } else {
    jwt.verify(token, secret, function (err, res) {
      if (err) {
        res.status(401).send('Unauthorized: Invalid token');
      } else {
        req.email = res.email;
        next();
      }
    });
  }
}

module.exports = withAuth;