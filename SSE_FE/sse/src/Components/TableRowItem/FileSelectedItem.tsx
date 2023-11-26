import React, { useEffect, useState } from 'react'

const FileSelectedItem = ({file}:any)=>{
    var filesToSelect:any = [];
    const[checkBox,setCheckBox]= useState<any>()
    useEffect(()=>{
      //localStorage.setItem('files','');
      const storedData:any = localStorage.getItem('files')
      const selected = localStorage.getItem('files') ? JSON.parse(storedData): []
      setCheckBox(selected)
    },[])

    if(!localStorage.getItem('files')){
        localStorage.setItem('files',filesToSelect)
    }
  
    const handleChange = (fileSelected:string)=>{
      
        const storedData:any = localStorage.getItem('files')
        const selected = localStorage.getItem('files') ? JSON.parse(storedData): []
        
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
        localStorage.setItem('files', JSON.stringify(selected));
        
      
        
    }
    return <>
  <thead>
    
    <tr>
      <th scope="col" style={{'width':'100%'}}>{file.name}</th>
      <th scope="col"><input type="checkbox" checked={checkBox?.find((check: any) => check.name === file.name)?.checked} onChange={()=>handleChange(file.name)}/></th>

    </tr>
  </thead>

    </>
}

export default FileSelectedItem