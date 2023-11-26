import React, { useEffect, useRef, useState} from 'react'
import { DialogBox } from '../../Components/DialogBox'
import InputField from '../../Components/FormControl/InputField'
import Button from '../../Components/FormControl/Button'
import useAPI from '../../Hooks/useFetch'
import imgLoading from '../../img/loading.gif'

import './home.css'
import Alert from '../../Components/Alert'
import { Table } from '../../Components/Table'
import TableRow from '../../Components/TableRow'
import FileSelectedItem from '../../Components/TableRowItem/FileSelectedItem'
import EncFileSelectedItem from '../../Components/TableRowItem/EncFileSelectedItem'

type HomeDialogBoxProp = {
    id:string,
    title:string
}
const HomeDialogBox = ({id,title}:HomeDialogBoxProp)=>{
    const {data,error,loading,setLoading,postData,uploadProgress,secret,fetchData} = useAPI()
    const inputRef = useRef<HTMLInputElement|null>(null);
    const[path,setPath]=useState('')
    const[showAlert,setShowAlert]=useState(false)
    const [isEncrypt,setIsEncrypt]= useState(false)

    useEffect(()=>{
        //const inputRef = useRef<HTMLInputElement|null>(null);
        //inputRef.current = null;
    },[isEncrypt])
    let selectedEncFiles= [];
    const handleFolderChange = (e: any) => {
        const files = e.target.files;
        if (files && files.length > 0) {
          const folderPath = files[0].webkitRelativePath.split('/')[0];
          fetchData(`http://127.0.0.1:8000/fetch-files/${folderPath}`)
          setPath(folderPath)
        }
      };
    
      const handleClick = () => {
        if (inputRef.current) {
            inputRef.current.type = 'file';
            (inputRef.current as any).webkitdirectory = true;
            inputRef.current.click();
          }
      };

  
    const generateKey = (key:string)=>{
    postData('POST',`http://127.0.0.1:8000/generate-secret-key/${key}/${localStorage.getItem('user_id')}`)
   
    }
    if(id==="upload"){
        const selectedFiles:any = localStorage.getItem('fileEnc');
        selectedEncFiles  = localStorage.getItem('fileEnc') ? JSON.parse(selectedFiles): []

    }
    const encrypt = ()=>{
        if(path==""){
            alert("Please select folder path")
        }
        const selectedFiles:any = localStorage.getItem('files');
        const allFiles  = localStorage.getItem('files') ? JSON.parse(selectedFiles): []
        const files:any = [];
        const toSubmit:any = [];
        allFiles?.filter((file:any)=>{
             if(file.checked==true)
             {
                files.push(file.name)
                toSubmit.push(file)
            }
            })
            setIsEncrypt(true)
        localStorage.setItem('fileEnc',JSON.stringify(toSubmit))
        postData('POST',`http://127.0.0.1:8000/encrypt/${localStorage.getItem('user_id')}`,{'path':path,'files':files})

            //inputRef.current = null;
           // inputRef.current?.focus()


    }

    const upload = ()=>{
        setLoading(true)
        setShowAlert(true)
        const selectedFiles:any = localStorage.getItem('fileEnc');
        const allFiles  = localStorage.getItem('fileEnc') ? JSON.parse(selectedFiles): []
        const files:any = []
        allFiles?.forEach((file:any)=>{
             if(file.checked==true)
             {
                files.push(file.name)
            }
            })
        postData('POST',`http://127.0.0.1:8000/upload/${localStorage.getItem('user_id')}`,{'files':allFiles})  
        localStorage.setItem('fileEnc','')  
        localStorage.setItem('files','')   
          
    }

    useEffect(()=>{
        fetchData(`http://127.0.0.1:8000/fetch-key/KG/${localStorage.getItem('user_id')},http://127.0.0.1:8000/fetch-key/KSKE/${localStorage.getItem('user_id')}`)

    },[])

return <>
                <DialogBox id={id}>
                    <DialogBox.Head  isCloseBtn={true} title={title}/>
                    <DialogBox.Body>
                        <form>  
                            {id==='secretkey' && <>
                            <InputField  id="cname" label='KG' type='text' value={secret.kg} name="kg" disabled={true}/>
                                <div className='password-group'>
                                <Button  btnType='primary' small={true}  name='Generate' id='generate' type='button' onClick={()=>generateKey('KG')}/>
                                <div className="password-group-item">
                                <Button btnType='secondary' small={true}  id='generate' type='button'><i className="fas fa-eye-slash"></i>  </Button>
                                 </div> 
                                </div>     
                        <InputField  id="ounit" label='KSKE' name="kske" value={secret.kske} disabled={true}/>
                        <div className='password-group'>
                                <Button  btnType='primary' small={true}  name='Generate' id='generate' type='button' onClick={()=>generateKey('KSKE')} />
                                <div className="password-group-item">
                                <Button btnType='secondary' small={true}  id='generate' type='button'><i className="fas fa-eye-slash"></i>  </Button> 
                                </div>
                                </div>
                            </>} 
                            {
                                id==='encrypt' && 
                                <>
                                    <div className="container">
                                    <div className="form-group">
                                    <label htmlFor="folderPath">Folder Path:</label>
                                    <div className="input-group">
                                    <input
                                        type="text"
                                        className="form-control"
                                        id="folderPath"
                                        readOnly
                                        value={path}
                                    />
                                    <div className="input-group-append">
                                        <button type="button" className="btn btn-outline-primary" onClick={handleClick}>
                                        Select Folder
                                        </button>
                                        <input
                                        ref={inputRef}
                                        onInput={handleFolderChange}
                                        onSelect={handleFolderChange}
                                        onChange={handleFolderChange}
                                        onClick={handleFolderChange}
                                        multiple={false}
                                        style={{ display: 'none' }}
                                        />
                                    </div>
                                    </div>
                                    {isEncrypt && !loading && <Alert message="File successfully Encrypted" duration={2000} type="success" />}
                                    <Table>
                                    <Table.Body>   
                                        <TableRow  items={data} DataResource="file" DataComponent={FileSelectedItem}  />
                                    </Table.Body>
                                </Table> 
                                </div>
                                </div>   
     
                                </>
                            }
                            {
                                id==='upload' && <div className='upload-button'>
                                {loading && <img src={imgLoading}  style={{margin:'1rem 0rem'}} width="40px" height="40px"/>}
                                {showAlert && !loading && <Alert message="File successfully updated to the server" duration={2000} type="success" />}
                                <Table>
                                    <Table.Body>
                                        <TableRow  items={selectedEncFiles} DataResource="file" DataComponent={EncFileSelectedItem}  />
                                    </Table.Body>
                                </Table> 
                                <Button name='Upload' id="fileupload" btnType='success' small={true} onClick={upload} type='button'/>
                                </div> 
                            }

                        </form>
                        
                    </DialogBox.Body>
                    {
                        id==='encrypt' &&      <DialogBox.Foot>
                        <Button  btnType='secondary' small={true}  name='Close' id='close' dismiss={true} type='button' data-bs-dismiss="modal"/>
                        <Button name='Encrypt' id="save" btnType='primary' small={true} onClick={encrypt} type='button' dismiss={true}/>
                        </DialogBox.Foot>
                    }

                </DialogBox></>

}

export default HomeDialogBox