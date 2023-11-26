import React, { ChangeEvent } from "react";

type InputFieldProp = {
    label?:string,
    type:'text'|'password'|'email',
    placeholder?:string,
    value?:string,
    name?:string,
    id?:string
    onChange?:(event: ChangeEvent<HTMLInputElement>) => void;
}
 const InputField = ({label,type,placeholder,value,onChange,id,name}:InputFieldProp)=>{

return <>

<div className="form-group">
    {label? <label htmlFor="exampleInputPassword1">{label}</label>: '' }		
			<input type={type} className="form-control" id={id}  onChange={onChange} value={value} name={name} placeholder={placeholder}/>
	</div>
</>
}

export default InputField