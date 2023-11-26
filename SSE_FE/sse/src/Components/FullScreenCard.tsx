import React, { ReactNode } from 'react';
import '../Layout/AuthLayout.css'

type FullScreenCardProps={
children:ReactNode
}
export const FullScreenCard = ({children}:FullScreenCardProps)=>{

    return <div className='fullscreencard'>
        
            {children}
        
    </div>
}

FullScreenCard.Body = ({children}:FullScreenCardProps)=>{

    return <div style={{minWidth:'300px',backgroundColor:'white',padding:'1rem',boxShadow: '0 0 10px rgba(0, 0, 0, 0.2)'}}>
    {children}
    </div>
}


FullScreenCard.Below = ({children}:FullScreenCardProps)=>{
    return <>
        {children}
    </>
}
