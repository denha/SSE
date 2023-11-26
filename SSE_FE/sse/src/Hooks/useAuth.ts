import { useEffect } from "react"
import { useFetchUser } from "./useFetchUser"
import { useLocalStorage } from "./useLocalStorage"
import { useNavigate } from "react-router-dom"


export const useAuth= ()=>{

    const {error,user,setLoginCred,loginCred}= useFetchUser()
    const {addItem}=useLocalStorage()
    const navigate = useNavigate();
    useEffect(()=>{
        if(user){
            addItem("email",user.email)
            addItem("key",user.key)
            addItem("user_id",user.user_id)
            if(loginCred){
                addItem("data_owner_id",loginCred.role) 
            }
            user.role ==="data_owner" ? navigate("/home") : navigate("/search");
            ;
        }
    },[user])

return {error,user,setLoginCred}

}