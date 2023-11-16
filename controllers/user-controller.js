const User = require("../models/User");
const bcrypt = require('bcryptjs');
const otpGenerator = require('otp-generator');
const nodemailer = require('nodemailer');


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'test.backendverify@gmail.com',
      pass: 'kkfapdrqmihzoyat',
    },
});

const getAllUser = async(req,res,next) => {
    let users;
    try{
        users = await User.find();
    } catch(err) {
        console.log(err);
    }

    if(!users){
        return res.status(404).json({message: "No Users Found"});
    }
    return res.status(200).json({users});
}

const signup = async (req, res, next) => {
    const { name, username, birthdate, email, password } = req.body;

    let existingUser;
    try {
        existingUser = await User.findOne({ email });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Internal Server Error' });
    }

    if (existingUser) {
        return res.status(400).json({ message: 'User Already Exists! Try Logging In' });
    }

    const hashedPassword = bcrypt.hashSync(password);
    const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });

    const user = new User({
        name,
        username,
        birthdate,
        email,
        password: hashedPassword,
        otp,
        isVerified: false,
        blogs: [],
    });
    await user.save();
    try {
        const mailOptions = {
            from: 'test.backendverify@gmail.com',
            to: email,
            subject: 'OTP for Email Verification',
            text: `Your OTP is: ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ message: 'Error sending email' });
            }
            return res.status(201).json({ message: 'OTP Sent' });
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Error sending OTP' });
    }
};


const verifyOTP = async (req, res, next) => {
    const { email, otp } = req.body;
    console.log('Received OTP Verification Request:', { email, otp });
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      if (user.otp === otp) {
        user.isVerified = true;
        await user.save();
        return res.status(200).json({ isVerified: true, user });
      } else {
        return res.status(200).json({ isVerified: false });
      }
    } catch (error) {
        console.error('Error updating user:', error);
        return res.status(500).json({ message: 'Error updating user' });
    }
};

const login = async(req,res,next) => {
    const { email,password } = req.body;
    let existingUser;
    try{
        existingUser = await User.findOne({email});
    } 
    catch (err) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
    
    if (!existingUser) {
        return res.status(404).json({ message: "Couldn't Find User By This Email" });
    }

    if (!existingUser.isVerified) {
        return res.status(403).json({ message: "User not verified. Please complete the verification process." });
    }

    const isPasswordCorrect = bcrypt.compareSync(password, existingUser.password);
    if (!isPasswordCorrect) {
        return res.status(400).json({ message: "Incorrect Password" });
    }
    return res.status(200).json({ message: "Login Successful", user: existingUser });
    
}

module.exports = {getAllUser, signup, login, verifyOTP};