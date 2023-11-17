const express = require('express');
const { getAllUser, signup, login, deleteAccount, ChangePwd } = require('../controllers/user-controller');

const router = express.Router();

router.get("/", getAllUser);
router.post("/signup",signup);
router.post("/login", login);
router.delete("/deleteAccount", deleteAccount);
router.post("/ChangePwd",ChangePwd);

module.exports = {router}