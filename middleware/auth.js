const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function (req, res, next) {
  //Get the token from header
  const token = req.header('x-auth-token');

  //Check if no token given
  if (!token) {
    return res.status(401).json({
      msg: 'No token, Unauthorised to view',
    });
  }

  //Verify token
  try {
    const decoded = jwt.verify(token, config.get('jwtSecret'));
    //Save the user from token to the response user and can be further used in coming authorized flow
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({
      msg: 'Token is not valid.',
    });
  }
};
