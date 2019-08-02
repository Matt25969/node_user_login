const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");

const User = require("../models/user");

const validateUserInput = require("../validation/User");

// @route   GET user/all
// @desc    Get all users
// @access  Public
router.get("/all", (req, res) => {
  const errors = {};
  User.find({}, "-password -email")
    .then(users => {
      if (!users) {
        errors.noUsers = "There are no users";
        res.status(404).json(errors);
      }

      res.json(users);
    })
    .catch(err => res.status(404).json({ noUsers: "There are no users" }));
});

// @route   GET user/name/:username/:password
// @desc    Get all users from one name
// @access  Public
router.get("/name/:username/:password", (req, res) => {
   
  const errors = {};
  User.find({ username: req.params.username })
    .then(user => {

      console.log(user)

      if (user.length===0) {
        errors.noUser = "There are no users with this username";
        res.status(404).json(errors);
      }

      bcrypt.compare(req.params.password, user[0].password).then(isMatch => {
        if (isMatch) {
          res.json({Status : "Logged In"}).status(200).send();
        }else{
          res.json({Status : "Not Logged In"}).status(200).send();
        }
    })
    .catch(err => res.status(404).json(err));
});
})

// @route   POST user/createuser
// @desc    Create a user
// @access  Public
router.post("/createUser", (req, res) => {

  const { errors, isValid } = validateUserInput(req.body);
  if (!isValid) {
    return res.json(errors);
  }
  
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password
  });

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (err, hash) => {
      if (err) throw err;
      newUser.password = hash;
      newUser.save().then(item => res.json({Status:"Account successfully created"}))
        .catch(err => console.log(err));
    });


});
})

// @route   PUT user/updateuser
// @desc    Update first user **UNSECURE**
// @access  Public
router.put("/updateuser", (req, res) => {

  const { errors, isValid } = validateUserInput(req.body);
  if (!isValid) {
    return res.status(400).json(errors);
  }

  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password
  });

  User.findOne({_id:req.body._id})
    .then(user => {
      if (!user) {
        errors.noUser = "There are no users with this ID";
        res.status(404).json(errors);
      }

      User
        .remove({_id:req.body._id})
        .then(() => {
          res.json({ success: true });
        })
        .catch(err =>
          res.status(404).json({ usernotfound: "No user found" })
        );

      newUser.save().then(user => res.json(user))
        .catch(err => console.log(err));

    })
    .catch(err => res.status(404).json(err));

});

// @route   DELETE user/deleteuser
// @desc    Delete first user **UNSECURE**
// @access  Public
router.delete("/deleteUser/:_id", (req, res) => {

  let errors = {};

  const _id = req.params._id;

  User.findById(_id).then(user => {

        User
          .remove({_id:_id})
          .then(() => {
            res.json({ success: true });
          })
          .catch(err =>
            res.status(404).json({ usernotfound: "No user found" })
          );

      } 

  ).catch(err => res.status(404).json({ nouser: "There is no user with this ID" }));

});

module.exports = router;
