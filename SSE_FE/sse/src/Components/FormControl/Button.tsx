import React from 'react'

import { ButtonProp } from '../../types'

const Button = ({name,id,type,className,dataTarget,dataToggle,small,btnType,onClick,children,dismiss=false}:ButtonProp)=>{
    let classbtn='',classBtnType=''
    if (small){
        classbtn ='btn-sm'
    }
    if(btnType=='secondary'){
        classBtnType='btn btn-secondary'
    }else if(btnType=="primary"){
        classBtnType="btn btn-primary"
    }else if(btnType=="success"){
        classBtnType="btn btn-success"
    }
return <button name={name} className={`${classBtnType} ${className} ${classbtn}`} 
id={id} type={type} data-toggle={dataToggle} data-target={dataTarget} onClick={onClick}  data-dismiss={dismiss? 'modal': ''}>
{name}
{children}
</button>

}

export default Button