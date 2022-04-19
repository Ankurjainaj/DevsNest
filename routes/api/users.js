const express = require('express');
const router = express.Router();

const { check, validationResult } = require('express-validator/check');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
  '/',
  [
    check('name', 'Nme is a Required field').notEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please add a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  (req, res) => {
    // console.log(req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    res.send('User route');
  }
);

module.exports = router;
