import React from "react";

import  './AuthLayout.css'
import { FullScreenCard } from "../Components/FullScreenCard";
import { Outlet } from "react-router-dom";

const AuthLayout = ()=>{
return <>
    <FullScreenCard>
        <FullScreenCard.Body>
        <Outlet/>
        </FullScreenCard.Body>
    </FullScreenCard>
   
        
    
</>
}

export default AuthLayout