import React, { useState } from 'react'
import { Link } from 'react-router-dom';
import { attributData, roleData } from '../../Data/data';
import InputField from '../../Components/InputField';
import InputFieldSelect  from '../../Components/FormControl/InputField';
import useAPI from '../../Hooks/useFetch';
import Alert from '../../Components/Alert';

const Register = ()=>{
    const {postData,data,loading}= useAPI()
    const defaultUser = {username:'',email:'',password:'',role:'data_owner',cpassword:'',attr:''}
    const [user,setUser]=useState(defaultUser)
    const[showAlert,setShowAlert]=useState(false)
    const handleChange = (event:any)=>{
        setUser({...user,[event.target.name]:event.target.value})
        
    }

    const register = ()=>{
        if(user.email==""){
            alert("Email cannot be empty")
        }
        if(user.username==""){
            alert("Username cannot be empty")
        }
        if(user.password==""){
            alert("Password canot be empty")
        }
        if(user.password!==user.cpassword){
            alert("Password dont match")
        }
        setShowAlert(true)
        postData("POST","http://127.0.0.1:8000/user-add",user)
        setUser(defaultUser)
        
    }
return <>

{showAlert && !loading && <Alert message="User successfully created" duration={2000} type="success" />}
<h4 className='text-center'> Register</h4>
	<form >
         <InputField label='Username'  type='text' name="username" value={user.username} onChange={handleChange}/>
         <InputField label='Email'  type='text' name="email" value={user.email}  onChange={handleChange}/>
         <InputFieldSelect label='Role' type='dropdown' id='role' value={user.role} name="role" data={roleData} onChange={handleChange}/>
         {user.role=="user" && <InputFieldSelect label='Attributes' type='dropdown' id='attr' value={user.attr} name="attr" data={attributData} onChange={handleChange}/>}
         <InputField label='Password'  type='password' name="password" value={user.password} onChange={handleChange}/>
         <InputField label='Confirm Password'  type='password' name="cpassword" value={user.cpassword} onChange={handleChange}/>
		<button type="button"  className="btn btn-primary" onClick={register}>Submit</button>  
	</form>
    <p className='text-center' style={{fontSize:'13px'}}>
        <Link to={'/login'}>Login</Link>
    </p>
</>
}

export default Register;