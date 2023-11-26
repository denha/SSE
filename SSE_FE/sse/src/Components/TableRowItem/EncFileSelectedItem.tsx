import React, { useEffect, useState } from 'react'

const EncFileSelectedItem = ({file}:any)=>{
    var filesToSelect:any = [];
    const[checkBox,setCheckBox]= useState<any>()
   
    useEffect(()=>{
      const storedData:any = localStorage.getItem('fileEnc')
      const selected = localStorage.getItem('fileEnc') ? JSON.parse(storedData): []
      const fileResults = selected?.filter((file:any)=>file.checked=true)
   localStorage.setItem('fileEnc', JSON.stringify(fileResults));
   setCheckBox(selected)
    },[])

    if(!localStorage.getItem('files')){
        localStorage.setItem('files',filesToSelect)
    }
  
    const handleChange = (fileSelected:string)=>{
      
        const storedData:any = localStorage.getItem('fileEnc')
        const selected = localStorage.getItem('fileEnc') ? JSON.parse(storedData): []
        
        const fileResults = selected?.find((file:any)=>{
            if(file.name===fileSelected){
                file.checked = !file.checked;
                return file;
            }
        })
            
        if(!fileResults){
            selected.push({'name':fileSelected,'checked':true,'id':fileSelected})
   
        }
        setCheckBox(selected)
        localStorage.setItem('fileEnc', JSON.stringify(selected));
        
      
        
    }
    return <>
  <thead>
    
    <tr>
      <th scope="col" style={{'width':'100%'}}>{file.name.replace('.txt','.txt.enc')}</th>
      <th scope="col"><input type="checkbox" onChange={()=>handleChange(file.name)}
      checked={checkBox?.find((check: any) => check.name === file.name)?.checked}
      /></th>

    </tr>
  </thead>

    </>
}

export default EncFileSelectedItem