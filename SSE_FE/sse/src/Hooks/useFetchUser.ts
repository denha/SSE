import { useEffect, useState } from "react"
import axios from "axios"

import { user, userLoginData } from "../types"



export const useFetchUser = ()=>{
    const [user,setUser] = useState<user>()
    const [error,setError]=useState<string|null>()
    const [loginCred,setLoginCred]= useState<userLoginData>({email:'',password:'',role:''})

    useEffect(()=>{
        if(loginCred.email && loginCred.password){
            fetchUser(loginCred.email,loginCred.password)
        }
        
    },[loginCred])



    const fetchUser = async (email:string,password:string)=>{
        const  url= 'http://127.0.0.1:8000/user-login'
        try{

            const results = await axios.post(url,{email,password})
            if(results.status===200){

                if(!results.data.status)
                    throw Error(results.data.message)
                setUser(results.data.data)       
                
            }else{
                throw Error("unknown error")
            }
        }catch(e){

            if( e instanceof Error)
                setError(e.message)
            
        }


    }
    return {error,user,setLoginCred,loginCred}
}

