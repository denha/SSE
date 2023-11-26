import React, { useEffect, useState } from 'react';

import InputField from '../../Components/InputField';
import InputFieldSelect from '../../Components/FormControl/InputField';

import { Link } from 'react-router-dom';

import { useAuth } from '../../Hooks/useAuth';
import useAPI from '../../Hooks/useFetch';

const Login = ()=>{
   
    const {error,user,setLoginCred}=useAuth()
    const [email,setEmail] = useState("")
    const [password,setPassword] = useState("")
    const [role,setRole]=useState("")
   
    const loginRequest = ()=>{
        setLoginCred({email,password,role})
        
    }

    const {fetchData,data}=useAPI()

    useEffect(()=>{
        fetchData("http://127.0.0.1:8000/data-owner")
    },[])
    //let data = data?.unshift()
return <>
<h4 className='text-center'> Login</h4>
	<form >
         <InputField label='Email' value={email} placeholder='Enter email address' onChange={(e)=>setEmail(e.target.value)} id="email" type='email' />
         <InputField label='Password' value={password} placeholder='Enter password' onChange={(e)=>setPassword(e.target.value)} id="password"  type='password'/>
         {/*<InputFieldSelect label='Data Owner' type='dropdown' data={data} id='role'  onChange={(e:any)=>setRole(e.target.value)}/>*/}
         {error &&<p style={{color:'red'}}>{error}</p>}
		<button type="button" className="btn btn-primary" onClick={loginRequest}  >Login</button>  
	</form>
    <p className='text-center' style={{fontSize:'13px'}}>
       <Link to={'/register'} >Create Account</Link> 
    </p>
</>

}

export default Login;