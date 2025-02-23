const mongoose=require('mongoose');
const validator=require('validator');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcrypt');

const userSchema=new mongoose.Schema({
    userName:{
        type:String,
        required:true,
        minLength:[3,'user name should be at least 3 characters long!'],
        maxLength:[10,'user name should be at most 10 characters long '],
        trim:true,
    },
    firstName:{
        type:String,
        required:true,
        minLength:[3,'first name should be at least 3 characters long '],
        maxLength:[10,'first name should be at most 10 characters long'],
        trim:true,
    },
    lastName:{
        type:String,
        minLength:[1,'last name should be at least 1 character long '],
        maxLength:[10,'last name should be at most 10 characters long '],
        trim:true,
    },
    emailId:{
        type:String,
        minLength:[10,'email address should be at least 10 characters long'],
        maxLength:[30,'email address shou be at most 10 characters long '],
        required:true,
        unique:true,
        trim:true,
        validate(value){
            if(!validator.isEmail(value)){
                throw new Error('Invalid email address! '+value);
            }
        }
    },
    password:{
        type:String,
        required:true,
        trim:true,
        validate(value){
            if(!validator.isStrongPassword(value)){
                throw new Error('Password is not strong password!');
            }
        },
    },
    avatar:{
        type:String,
        default:"https://cdn-icons-png.flaticon.com/128/18831/18831913.png",
        validate(value){
            if(!validator.isURL(value)){
                throw new Error('Invalid Image URL...');
            }
        },
    },
    refreshToken:{
        type:String,
        default:null,
    }
},{timestamps:true});

userSchema.methods.getAccessToken=async function(){
    const user=this;
    const token=jwt.sign({_id:user._id},process.env.ACCESS_TOKEN_SECRET,{
        expiresIn:'1h'
    });
    return token;
}

userSchema.methods.getRefreshToken=async function(){
    const user=this;
    const token=jwt.sign({_id:user._id},process.env.REFRESH_TOKEN_SECRET,{
        expiresIn:'7d'
    });
    return token;
}


userSchema.methods.validatePassword=async function(passwordInputByUser){
    const user=this;
    const hashedPassword=user.password;
    const isPasswordValid=await bcrypt.compare(passwordInputByUser,hashedPassword);
    return isPasswordValid;
}

const User=mongoose.model('User',userSchema);
module.exports={User};