const express = require("express");
const router = express.Router();

const User = require("../models/user");

const validateUserInput = require("../validation/User");

// @route   GET user/all
// @desc    Get all users
// @access  Public
router.get("/all", (req, res) => {
  const errors = {};
  User.find({})
    .then(users => {
      if (!users) {
        errors.noUsers = "There are no users";
        res.status(404).json(errors);
      }

      res.json(users);
    })
    .catch(err => res.status(404).json({ noUsers: "There are no users" }));
});

// @route   GET user/name/:username
// @desc    Get all users from one name
// @access  Public
router.get("/name/:username", (req, res) => {
  const errors = {};
  User.find({ username: req.params.username })
    .then(users => {
      if (!users) {
        errors.noUsers = "There are no users";
        res.status(404).json(errors);
      }
      res.json(users);
    })
    .catch(err => res.status(404).json({ noUsers: "There are no users" }));
});

// @route   POST user/createuser
// @desc    Create a user
// @access  Public
router.post("/createUser", (req, res) => {
  
  const { errors, isValid } = validateUserInput(req.body);
  if (!isValid) {
    console.log(errors)
    return res.json(errors);
  }
  
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password
  });

  newUser.save().then(user => res.json(user))
        .catch(err => console.log(err));

});

// @route   PUT user/updateuser
// @desc    Update first user
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
// @desc    Delete first user
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
