const validator=require('validator')

const verifySignUpData=(req)=>{
    const {userName,firstName,lastName,emailId,password}=req.body;
    if(!userName){
        throw new Error('user name is required!');
    }
    if(!firstName||!lastName){
        throw new Error('Name should be valid!');
    }
    if(!validator.isEmail(emailId)){
        throw new Error('Please enter a valid email address');
    }
    if(!validator.isStrongPassword(password)){
        throw new Error('Password should be strong!');
    }
};

module.exports={verifySignUpData};
