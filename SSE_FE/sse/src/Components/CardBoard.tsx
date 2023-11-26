import React from 'react'

import { ReactChildProp,CardBoardHead,CardBoardBodyProp,CardBoardProp} from '../types'

export const CardBoard =({children,className,onClick,dataTarget,dataToggle}:CardBoardProp)=>{

  return <div className={`card ${className}`} onClick={onClick} data-toggle={dataToggle} data-target={dataTarget}>
    {children}
  </div>
}

 CardBoard.Head = ({children,icon}:CardBoardHead)=>{
  return  <div className="card-header">
    <>
    <i className={icon}></i>
    {children}
    </>
  </div>

}

CardBoard.Body = ({children,className}:CardBoardBodyProp)=>{
return <div className={`card-body ${className}`}>
{children}
</div>
}

