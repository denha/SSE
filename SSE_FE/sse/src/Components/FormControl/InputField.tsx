import React from "react";

import { InputFieldProp } from "../../types";

const InputField = ({label,id,name,type='text',data,onChange,value,disabled}:InputFieldProp)=>{
let dropdown;

if(type=='dropdown'){
   dropdown =  data?.map((data:any)=>(
    <option key={data.id} value={data.id}>{data.value}</option>
    ))
}

return  <div className='form-group'>
<label htmlFor="him">{label}</label>
{
    type ==='text' && <input type={type}  id={id} name={name} className='form-control form-control-sm' onChange={onChange} disabled={disabled} 
    value={value}/>
}
{
    type ==='password' && <input type={type}  id={id} name={name} className='form-control form-control-sm' onChange={onChange} disabled={disabled} 
    value={value}/>
}
{
    type==='dropdown' && <select className=" form-control form-select" id={id} name={name} onChange={onChange} >
    {dropdown}
  </select>
}
</div>

}

export default InputField