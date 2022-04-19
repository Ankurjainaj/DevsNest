const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

const { check, validationResult } = require('express-validator');

//User Model
const User = require('../../models/User');
const { default: mongoose } = require('mongoose');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
  '/',
  [
    check('name', 'Name is a Required field').notEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please add a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    // console.log(req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    try {
      let user = await User.findOne({ email });

      //See if user exists
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User Already exists' }] });
      }

      //Get users gravatar
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm',
      });

      user = new User({
        name,
        email,
        password,
        avatar,
      });

      //Encrypt password
      const salt = await bcrypt.genSalt(10); //Salt for encryption
      user.password = await bcrypt.hash(password, salt);

      await user.save(); //Saves the user in DB

      //Return jsonwebtoken (jwt)
      const payload = {
        //Payload for jwt refer jwt.io
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {
          expiresIn: 360000, //Token expires in 360000 seconds
        }, //Callback:
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
      //   res.send('User registered');
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  }
);

module.exports = router;
