require('dotenv').config();
const express=require('express');
const cookieParser=require('cookie-parser');
const cors=require('cors');
const helmet=require('helmet');
const rateLimit=require('express-rate-limit');
const {connectDB}=require('./config/database.js')

const app=express();
const limiter=rateLimit({
    windowMs:15*60*1000,
    max:100,
    message:'We received too many requests from this IP, please try again later!' 
})

app.use(helmet());
app.use(limiter);
app.use(express.json());
app.use(cors({
    origin:process.env.FRONTEND_URL,
    credentials:true
}));
app.use(cookieParser());

const {authRouter}=require('./routes/authRoutes');
app.use('/',authRouter);





connectDB()
    .then(()=>{
        console.log("Connected to MongoDB successfully!");
        app.listen(process.env.PORT,()=>{
            console.log(`Server running on port ${process.env.PORT}`);
         });
        })
    .catch((err)=>{
        console.log(`Connection to MongoDB failed: ${err}`);
    });