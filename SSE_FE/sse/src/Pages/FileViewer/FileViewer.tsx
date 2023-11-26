import React, { useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import useAPI from "../../Hooks/useFetch";
import ImgLoader from '../../img/loading.gif'
import './index.css';

const FileViewer = ()=>{
const {file}= useParams()
const navigate = useNavigate();
const {fetchData,data,loading}=useAPI()

useEffect(()=>{
    fetchData(`http://127.0.0.1:8000/view-file/${file}/${localStorage.getItem('selectedDataOwner')}`)
},[])
console.log(file)
return<div className="file-viewer-container">
    <div className="file-viewer-heading">
    <button className="btn" onClick={() => {
        navigate(-1);
      }}><i className="fa fa-arrow-left"></i></button>
        <h6>Filename : {file?.slice(0,-4)}</h6>
    </div>
    {loading ?     <div className="loader">
     <img src={ImgLoader} width="60px" height="60px"/>
    </div> : 
         <div className="notepad">
         <pre className="notepad-content">{data}</pre>
       </div> }

 

</div>


}
export default FileViewer