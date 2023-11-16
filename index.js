const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { router } = require("./routes/user-routes");
const { blogRouter } = require("./routes/blog-routes");
const { verifyOTP } = require("./controllers/user-controller");

mongoose.set("strictQuery",true);
mongoose.connect("mongodb+srv://admin:wRU7qrkblljyHyGL@cluster0.8zikpwg.mongodb.net/?retryWrites=true&w=majority");
var db = mongoose.connection;
db.on("open",()=>console.log("Connected to DB"));
db.on("error",()=>console.log("Error occurred"));


const app = express();
app.use(cors());
app.use(express.json());
app.use("/api/user",router);
app.use("/api/blog",blogRouter);
app.post("/api/user/verify-otp", verifyOTP);

app.listen(4000,()=>{
    console.log("Server started at 4000");
})